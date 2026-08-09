"""Deterministic offline Phase 6D examples and outward-only practice evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.payload_integrity.building import build_plan as build_payload_plan
from omiv.payload_integrity.models import ObservedPayloadManifest, RootMode
from omiv.payload_integrity.observation import observe_payload
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubject, ProductSubjectClass
from omiv.safe_write import atomic_write_text
from omiv.tokenizer_parity.building import (
    build_added_token_observation,
    build_authority,
    build_catalog,
    build_declaration,
    build_evidence,
    build_execution,
    build_expectation,
    build_integration,
    build_pipeline_observation,
    build_plan,
    build_probe_execution,
    build_probe_results,
    build_probe_set,
    build_report,
    build_scenario,
    build_special_token_observation,
)
from omiv.tokenizer_parity.comparison import (
    build_comparison,
    build_policy,
    compare_added_tokens,
    compare_configurations,
    compare_merges,
    compare_pipelines,
    compare_probe_results,
    compare_special_tokens,
    compare_templates,
    compare_vocabularies,
    evaluate_policy,
    evaluate_vocabulary_size_rule,
)
from omiv.tokenizer_parity.models import (
    IDENTITY_SPECS,
    AddedTokenRecord,
    ArtifactAvailability,
    ArtifactBinding,
    AssetKind,
    AssetRole,
    ComponentSupportState,
    CoverageDimension,
    DenominatorState,
    ObjectReference,
    ParityFinding,
    ParityScope,
    PipelineComponentKind,
    PresenceState,
    ProbeComparisonStatus,
    ProbeInputAvailability,
    ProbeKind,
    ProbeOutputAvailability,
    SpecialTokenRecord,
    SpecialTokenRole,
    TokenContent,
    TokenizerConfigurationArtifactIndex,
    TokenizerConfigurationArtifactIndexEntry,
    TokenizerPipelineComponent,
    TokenizerProbeDefinition,
    TokenizerProbeResult,
    VocabularyCardinalityBasis,
    canonical_byte_token,
    canonical_probe_definition_id,
    canonical_text_token,
    finalize_identity,
    object_reference,
)
from omiv.tokenizer_parity.observation import (
    observe_chat_template,
    observe_json_configuration,
    observe_merge_table,
    observe_vocabulary_json,
)
from omiv.tokenizer_parity.reporting import pretty_json, render_markdown
from omiv.tokenizer_parity_profiles.xai import build_xai_readiness, render_xai_case_study
from omiv.trust.models import (
    BindingStatus,
    SignaturePurpose,
    SignedObjectType,
    SignerIdentityKind,
)
from omiv.trust.signing import (
    build_binding,
    build_descriptor,
    build_key_identity,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.signing import build_policy as build_trust_policy
from omiv.trust.verification import verify_envelope

FIXTURES: tuple[tuple[str, AssetRole, AssetKind], ...] = (
    ("config-reference.json", AssetRole.REFERENCE, AssetKind.MODEL_CONFIG),
    ("config-candidate.json", AssetRole.CANDIDATE, AssetKind.MODEL_CONFIG),
    ("vocab-reference.json", AssetRole.REFERENCE, AssetKind.VOCABULARY),
    ("vocab-candidate.json", AssetRole.CANDIDATE, AssetKind.VOCABULARY),
    ("merges-reference.txt", AssetRole.REFERENCE, AssetKind.MERGE_TABLE),
    ("chat-template-reference.txt", AssetRole.REFERENCE, AssetKind.CHAT_TEMPLATE),
)


def _write(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, pretty_json(value))


def _manifest_reference(value: ObservedPayloadManifest) -> ObjectReference:
    return ObjectReference(
        schema_id=value.schema_id,
        object_id=value.manifest_id,
        object_digest=value.manifest_digest,
    )


def _coverage(
    dimension: str, numerator: int, denominator: int | None, scope: ParityScope
) -> CoverageDimension:
    return CoverageDimension(
        dimension=dimension,
        numerator=numerator,
        denominator=denominator,
        denominator_state=(
            DenominatorState.AVAILABLE if denominator is not None else DenominatorState.UNAVAILABLE
        ),
        selected_scope=scope,
        incomplete_reason=(
            None
            if denominator is not None and denominator > 0 and numerator == denominator
            else "Coverage is unavailable, empty, or incomplete for this declared scope."
        ),
    )


def _full_coverage(probe_count: int) -> tuple[CoverageDimension, ...]:
    dimensions = (
        "REFERENCE_ARTIFACT_ASSETS",
        "CANDIDATE_ARTIFACT_ASSETS",
        "CONFIGURATION_FILES",
        "REQUIRED_CONFIGURATION_FIELDS",
        "VOCABULARY_ENTRIES",
        "VOCABULARY_IDS",
        "MERGE_RECORDS",
        "ADDED_TOKENS",
        "SPECIAL_TOKEN_ROLES",
        "TOKENIZER_PIPELINE_COMPONENTS",
        "CHAT_TEMPLATES",
        "PROBE_DEFINITIONS",
        "EXECUTED_PROBES",
        "TOKEN_ID_OUTPUTS",
        "DECODE_OUTPUTS",
        "BYTE_COVERAGE",
    )
    values = []
    for dimension in dimensions:
        count = (
            probe_count
            if dimension
            in {
                "PROBE_DEFINITIONS",
                "EXECUTED_PROBES",
            }
            else 1
        )
        values.append(
            _coverage(
                dimension,
                count,
                count,
                ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
            )
        )
    values.append(
        _coverage(
            "AUTHORITY_COVERAGE",
            1,
            1,
            ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
        )
    )
    return tuple(values)


def _phase6a_binding(
    repository: Path,
    output_root: Path,
    subject: ProductSubject,
    fixture_name: str,
) -> ObservedPayloadManifest:
    fixture = repository / "fixtures" / "tokenizer-parity" / fixture_name
    plan = build_payload_plan(
        subject,
        RootMode.SINGLE_FILE_ROOT,
        "tokenizer-fixture." + fixture_name.replace(".json", "").replace(".txt", ""),
        logical_name=fixture_name,
    )
    manifest, execution = observe_payload(fixture, plan)
    base = output_root / "tokenizer-configuration-parity" / "bindings"
    _write(base / f"{fixture_name}.manifest.json", manifest)
    _write(base / f"{fixture_name}.execution.json", execution)
    return manifest


def _artifact(
    manifest: ObservedPayloadManifest, role: AssetRole, kind: AssetKind
) -> ArtifactBinding:
    member = manifest.files[0]
    return ArtifactBinding(
        subject_id=manifest.subject.subject_id,
        role=role,
        asset_kind=kind,
        provider="omiv-synthetic",
        namespace="tokenizer-parity-fixtures",
        requested_revision="fixture-v1",
        resolved_revision="fixture-v1",
        phase6a_manifest=_manifest_reference(manifest),
        phase6b_snapshot=None,
        phase6c_evidence=None,
        artifact_set_identity=manifest.artifact_set_payload_digest,
        logical_root=manifest.logical_root,
        asset_path=member.path,
        file_size=member.size,
        payload_sha256=member.primary_content_digest.value,
        coverage="complete.declared-local-file-scope",
        availability=ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE,
        limitations=("Synthetic local fixture; not publisher evidence.",),
    )


def _probe(
    subject: ProductSubject,
    kind: ProbeKind,
    label: str,
    value: TokenContent | tuple[int, ...],
    identities: tuple[ObjectReference, ...],
) -> TokenizerProbeDefinition:
    inline = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    input_digest = canonical_sha256({"domain": "probe.input.v1", "value": inline})
    expected_output_form = (
        "token.ids" if kind == ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS else "decoded.text"
    )
    limitations = (f"Harmless synthetic input {label}; tokenizer was not executed by OMIV.",)
    body = {
        "probe_kind": kind,
        "subject_id": subject.subject_id,
        "scope": ParityScope.SELECTED_REQUIRED_PROBES,
        "input_availability": ProbeInputAvailability.INLINE_SYNTHETIC_INPUT,
        "input_digest": input_digest,
        "inline_input": value,
        "expected_output_form": expected_output_form,
        "tokenizer_identities": identities,
        "execution_context": "offline.synthetic.supplied-results",
        "limitations": limitations,
    }
    return TokenizerProbeDefinition(
        probe_id=canonical_probe_definition_id(body),
        probe_kind=kind,
        subject_id=subject.subject_id,
        scope=ParityScope.SELECTED_REQUIRED_PROBES,
        input_availability=ProbeInputAvailability.INLINE_SYNTHETIC_INPUT,
        input_digest=input_digest,
        inline_input=value,
        expected_output_form=expected_output_form,
        tokenizer_identities=identities,
        execution_context="offline.synthetic.supplied-results",
        limitations=limitations,
    )


def _probe_inputs() -> tuple[tuple[str, TokenContent], ...]:
    values = (
        ("empty", ""),
        ("ascii", "hello"),
        ("whitespace", " leading  trailing "),
        ("tab", "a\tb"),
        ("lf", "a\nb"),
        ("crlf", "a\r\nb"),
        ("nbsp", "a\u00a0b"),
        ("nfc", "é"),
        ("nfd", "e\u0301"),
        ("combining", "a\u0308"),
        ("cjk", "漢字"),
        ("japanese", "こんにちは"),
        ("emoji", "🙂"),
        ("variation", "✈️"),
        ("zwj", "👩‍💻"),
        ("rtl", "مرحبا"),
        ("punctuation", "!?—…"),
        ("special-looking", "<s></s>"),
        ("nul", "a\u0000b"),
        ("bounded-long", "x" * 256),
        ("unknown", "<unknown-synthetic>"),
    )
    result = [(name, canonical_text_token(value)) for name, value in values]
    result.append(("byte-sequence", canonical_byte_token(bytes.fromhex("00ff20"))))
    return tuple(result)


def _signed_examples(
    expectation: BaseModel, observation: BaseModel, evidence: BaseModel
) -> list[tuple[str, BaseModel]]:
    types = [
        SignedObjectType.TOKENIZER_CONFIGURATION_EXPECTATION,
        SignedObjectType.TOKENIZER_ASSET_OBSERVATION,
        SignedObjectType.TOKENIZER_CONFIGURATION_PARITY_EVIDENCE,
    ]
    purposes = [
        SignaturePurpose.TOKENIZER_CONFIGURATION_EXPECTATION_ISSUANCE,
        SignaturePurpose.TOKENIZER_ASSET_OBSERVATION_ISSUANCE,
        SignaturePurpose.TOKENIZER_CONFIGURATION_PARITY_EVIDENCE_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([109]) * 32)
    key = build_key_identity(private, allowed_object_types=types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic tokenizer parity evidence issuer",
        role="TOKENIZER_PARITY_EVIDENCE_ISSUER",
        evidence=[hashlib.sha256(b"omiv-phase6d-synthetic-issuer").hexdigest()],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    output: list[tuple[str, BaseModel]] = [
        ("signed/trust-policy.json", policy),
        ("signed/trust-bundle.json", bundle),
    ]
    for name, value, object_type, purpose in (
        ("expectation", expectation, types[0], purposes[0]),
        ("asset-observation", observation, types[1], purposes[1]),
        ("evidence", evidence, types[2], purposes[2]),
    ):
        raw = value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
        signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        report = verify_envelope(envelope, bundle, policy)
        output.append((f"signed/{name}.envelope.json", envelope))
        if name != "evidence":
            output.append((f"signed/{name}.signature-report.json", report))
    return output


def generate_all_tokenizer_configuration_examples(
    output_root: Path, *, repository: Path | None = None
) -> TokenizerConfigurationArtifactIndex:
    repository = (repository or Path.cwd()).resolve()
    output_root = output_root.resolve()
    subject = build_product_subject(
        ProductSubjectClass.TOKENIZER,
        "tokenizer.phase6d-synthetic",
        synthetic_scope(project="project.tokenizer-parity", environment="environment.offline"),
    )
    manifests = {
        name: _phase6a_binding(repository, output_root, subject, name)
        for name, _role, _kind in FIXTURES
    }
    bindings = {name: _artifact(manifests[name], role, kind) for name, role, kind in FIXTURES}
    bindings["merges-candidate.txt"] = bindings["merges-reference.txt"].model_copy(
        update={"role": AssetRole.CANDIDATE}
    )
    bindings["chat-template-candidate.txt"] = bindings["chat-template-reference.txt"].model_copy(
        update={"role": AssetRole.CANDIDATE}
    )
    required_fields = ("bos_token_id", "eos_token_id", "rope_scaling", "use_cache", "vocab_size")
    probe_kinds = (ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS, ProbeKind.DECODE_TOKEN_IDS_TO_TEXT)
    expectation = build_expectation(
        subject,
        scope=ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
        required_assets=(
            AssetKind.MODEL_CONFIG,
            AssetKind.VOCABULARY,
            AssetKind.MERGE_TABLE,
            AssetKind.CHAT_TEMPLATE,
        ),
        required_fields=required_fields,
        required_special_roles=(SpecialTokenRole.BOS, SpecialTokenRole.EOS),
        required_probe_kinds=probe_kinds,
    )
    reference = tuple(value for value in bindings.values() if value.role == AssetRole.REFERENCE)
    candidate = tuple(value for value in bindings.values() if value.role == AssetRole.CANDIDATE)
    declaration = build_declaration(subject, expectation, reference, candidate)
    supplied = tuple(_manifest_reference(value) for value in manifests.values())
    plan = build_plan(
        declaration,
        expectation,
        supplied,
        (binding.asset_path for binding in bindings.values()),
        scopes=(
            ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
            ParityScope.SELECTED_REQUIRED_PROBES,
        ),
    )
    execution = build_execution(
        plan,
        supplied,
        counters={
            "asset_files": len(bindings),
            "payload_bytes": sum(x.file_size or 0 for x in bindings.values()),
        },
    )
    one = (_coverage("CONFIGURATION_FILES", 1, 1, ParityScope.COMPLETE_DECLARED_CONFIGURATION),)
    config_ref_asset, config_ref = observe_json_configuration(
        repository / "fixtures/tokenizer-parity/config-reference.json",
        bindings["config-reference.json"],
        execution,
        required_fields,
        one,
    )
    config_cand_asset, config_cand = observe_json_configuration(
        repository / "fixtures/tokenizer-parity/config-candidate.json",
        bindings["config-candidate.json"],
        execution,
        required_fields,
        one,
    )
    vocab_ref_asset, vocab_ref = observe_vocabulary_json(
        repository / "fixtures/tokenizer-parity/vocab-reference.json",
        bindings["vocab-reference.json"],
        execution,
        (_coverage("VOCABULARY_ENTRIES", 5, 5, ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET),),
    )
    vocab_cand_asset, vocab_cand = observe_vocabulary_json(
        repository / "fixtures/tokenizer-parity/vocab-candidate.json",
        bindings["vocab-candidate.json"],
        execution,
        (_coverage("VOCABULARY_ENTRIES", 5, 5, ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET),),
    )
    merge_ref_asset, merge_ref = observe_merge_table(
        repository / "fixtures/tokenizer-parity/merges-reference.txt",
        bindings["merges-reference.txt"],
        execution,
        (_coverage("MERGE_RECORDS", 3, 3, ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET),),
    )
    merge_cand_asset, merge_cand = observe_merge_table(
        repository / "fixtures/tokenizer-parity/merges-reference.txt",
        bindings["merges-candidate.txt"],
        execution,
        (_coverage("MERGE_RECORDS", 3, 3, ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET),),
    )
    template_ref_asset, template_ref = observe_chat_template(
        repository / "fixtures/tokenizer-parity/chat-template-reference.txt",
        bindings["chat-template-reference.txt"],
        execution,
        language="jinja2-declared-not-executed",
    )
    template_cand_asset, template_cand = observe_chat_template(
        repository / "fixtures/tokenizer-parity/chat-template-reference.txt",
        bindings["chat-template-candidate.txt"],
        execution,
        language="jinja2-declared-not-executed",
    )
    added_records = (
        AddedTokenRecord(
            content=canonical_text_token("<s>"),
            token_id=1,
            token_id_presence=PresenceState.EXPLICIT_VALUE,
            special=True,
            single_word=False,
            lstrip=False,
            rstrip=False,
            normalized=False,
            property_presence=("special", "single_word", "lstrip", "rstrip", "normalized"),
            source_order=0,
            provenance="caller.supplied.synthetic",
        ),
    )
    added_ref = build_added_token_observation(execution, vocab_ref_asset, added_records, one)
    added_cand = build_added_token_observation(execution, vocab_cand_asset, added_records, one)
    special_records_ref = tuple(
        SpecialTokenRecord(
            role=role,
            content=canonical_text_token(content),
            content_presence=PresenceState.EXPLICIT_VALUE,
            token_id=token_id,
            token_id_presence=PresenceState.EXPLICIT_VALUE,
            added_properties=None,
            provenance="caller.supplied.synthetic",
            source_asset=object_reference(asset),
            declared_behavior="declared.special-token-role",
            availability=ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE,
        )
        for role, content, token_id, asset in (
            (SpecialTokenRole.BOS, "<s>", 1, vocab_ref_asset),
            (SpecialTokenRole.EOS, "</s>", 2, vocab_ref_asset),
        )
    )
    special_records_cand = tuple(
        record.model_copy(update={"source_asset": object_reference(vocab_cand_asset)})
        for record in special_records_ref
    )
    special_ref = build_special_token_observation(
        execution,
        (object_reference(vocab_ref_asset), object_reference(config_ref_asset)),
        special_records_ref,
        (),
        one,
    )
    special_cand = build_special_token_observation(
        execution,
        (object_reference(vocab_cand_asset), object_reference(config_cand_asset)),
        special_records_cand,
        (),
        one,
    )
    component_ref = TokenizerPipelineComponent(
        component_kind=PipelineComponentKind.MODEL,
        position=0,
        type_identifier="synthetic.bpe-descriptor",
        parameter_digest=canonical_sha256({"model": "synthetic.bpe-descriptor", "version": "v1"}),
        parameter_count=1,
        implementation_identifier=None,
        provenance="observed.structural-only",
        source_asset=object_reference(vocab_ref_asset),
        support_state=ComponentSupportState.STRUCTURALLY_OBSERVED,
        unknown_fields=(),
    )
    component_cand = component_ref.model_copy(
        update={
            "source_asset": object_reference(vocab_cand_asset),
        }
    )
    pipeline_ref = build_pipeline_observation(execution, vocab_ref_asset, (component_ref,), one)
    pipeline_cand = build_pipeline_observation(execution, vocab_cand_asset, (component_cand,), one)
    identities = (object_reference(vocab_ref), object_reference(vocab_cand))
    probes = tuple(
        _probe(subject, ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS, label, value, identities)
        for label, value in _probe_inputs()
    ) + (_probe(subject, ProbeKind.DECODE_TOKEN_IDS_TO_TEXT, "decode", (1, 2), identities),)
    probe_set = build_probe_set(subject, probes)
    probe_execution = build_probe_execution(plan, probe_set, identities)
    probe_results = tuple(
        TokenizerProbeResult(
            probe_id=probe.probe_id,
            probe_kind=probe.probe_kind,
            output_availability=ProbeOutputAvailability.INLINE_SYNTHETIC_OUTPUT,
            output_interpretation="canonical.synthetic.probe-result.v1",
            output_length=2 if probe.probe_kind == ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS else 7,
            token_ids=(index, index + 1)
            if probe.probe_kind == ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS
            else None,
            output_text=canonical_text_token("<s></s>")
            if probe.probe_kind == ProbeKind.DECODE_TOKEN_IDS_TO_TEXT
            else None,
            output_digest=canonical_sha256(
                {
                    "domain": "probe.output.v1",
                    "value": {
                        "probe_kind": probe.probe_kind,
                        "token_ids": (index, index + 1)
                        if probe.probe_kind == ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS
                        else None,
                        "token_contents": None,
                        "output_text": canonical_text_token("<s></s>").model_dump(mode="json")
                        if probe.probe_kind == ProbeKind.DECODE_TOKEN_IDS_TO_TEXT
                        else None,
                        "offsets": None,
                        "special_token_mask": None,
                        "attention_mask": None,
                        "interpretation": "canonical.synthetic.probe-result.v1",
                    },
                }
            ),
            status=ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES,
            limitations=("Supplied synthetic result; OMIV did not execute a tokenizer.",),
        )
        for index, probe in enumerate(probes)
    )
    probe_coverage = (
        _coverage(
            "EXECUTED_PROBES",
            len(probes),
            len(probes),
            ParityScope.SELECTED_REQUIRED_PROBES,
        ),
    )
    probe_ref = build_probe_results(probe_execution, probe_set, probe_results, probe_coverage)
    findings: list[ParityFinding] = []
    dimensions = []
    config_findings, config_status, config_dimension = compare_configurations(
        config_ref, config_cand, required_fields=required_fields
    )
    findings.extend(config_findings)
    dimensions.append(config_dimension)
    for current_findings, current_dimensions in (
        compare_vocabularies(vocab_ref, vocab_cand),
        compare_merges(merge_ref, merge_cand),
        compare_added_tokens(added_ref, added_cand),
        compare_special_tokens(special_ref, special_cand),
        compare_pipelines(pipeline_ref, pipeline_cand),
        compare_templates(template_ref, template_cand),
    ):
        findings.extend(current_findings)
        if isinstance(current_dimensions, tuple):
            dimensions.extend(current_dimensions)
        else:
            dimensions.append(current_dimensions)
    probe_findings, probe_status, probe_dimensions = compare_probe_results(probe_ref, probe_ref)
    findings.extend(probe_findings)
    dimensions.extend(probe_dimensions)
    coverage = _full_coverage(len(probes))
    observations = (
        config_ref,
        config_cand,
        vocab_ref,
        vocab_cand,
        merge_ref,
        merge_cand,
        added_ref,
        added_cand,
        special_ref,
        special_cand,
        pipeline_ref,
        pipeline_cand,
        template_ref,
        template_cand,
    )
    comparison = build_comparison(
        declaration,
        expectation,
        (object_reference(value) for value in observations),
        (object_reference(probe_ref),),
        findings,
        dimensions,
        coverage,
        configuration_status=config_status,
        probe_status=probe_status,
        scope=ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
        cross_asset=(
            evaluate_vocabulary_size_rule(
                config_ref,
                vocab_ref,
                field_path="vocab_size",
                basis=VocabularyCardinalityBasis.RECORD_COUNT,
            ),
        ),
    )
    authority = build_authority(subject, trusted_signer=True, publisher=False)
    policy = build_policy(
        subject,
        scope=ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET,
        required_assets=(
            AssetKind.MODEL_CONFIG,
            AssetKind.VOCABULARY,
            AssetKind.MERGE_TABLE,
            AssetKind.CHAT_TEMPLATE,
        ),
        required_fields=required_fields,
        required_special_roles=(SpecialTokenRole.BOS, SpecialTokenRole.EOS),
        required_pipeline_components=(PipelineComponentKind.MODEL,),
        required_probe_kinds=probe_kinds,
        require_authority=False,
    )
    policy_evaluation = evaluate_policy(comparison, policy, authority)
    evidence = build_evidence(comparison, policy_evaluation, authority)
    report = build_report(evidence, findings)
    xai_readiness, xai_case = build_xai_readiness(repository)
    objects: list[tuple[str, BaseModel]] = [
        ("expectations/synthetic.json", expectation),
        ("declarations/synthetic.json", declaration),
        ("plans/synthetic.json", plan),
        ("executions/synthetic.json", execution),
        ("observations/config-reference.asset.json", config_ref_asset),
        ("observations/config-candidate.asset.json", config_cand_asset),
        ("observations/config-reference.json", config_ref),
        ("observations/config-candidate.json", config_cand),
        ("observations/vocab-reference.asset.json", vocab_ref_asset),
        ("observations/vocab-candidate.asset.json", vocab_cand_asset),
        ("observations/vocab-reference.json", vocab_ref),
        ("observations/vocab-candidate.json", vocab_cand),
        ("observations/merges-reference.asset.json", merge_ref_asset),
        ("observations/merges-candidate.asset.json", merge_cand_asset),
        ("observations/merges-reference.json", merge_ref),
        ("observations/merges-candidate.json", merge_cand),
        ("observations/template-reference.asset.json", template_ref_asset),
        ("observations/template-candidate.asset.json", template_cand_asset),
        ("observations/template-reference.json", template_ref),
        ("observations/template-candidate.json", template_cand),
        ("observations/added-reference.json", added_ref),
        ("observations/added-candidate.json", added_cand),
        ("observations/special-reference.json", special_ref),
        ("observations/special-candidate.json", special_cand),
        ("observations/pipeline-reference.json", pipeline_ref),
        ("observations/pipeline-candidate.json", pipeline_cand),
        ("probes/definition.json", probe_set),
        ("probes/execution.json", probe_execution),
        ("probes/reference-results.json", probe_ref),
        ("comparisons/synthetic.json", comparison),
        ("policies/synthetic.json", policy),
        ("policy-evaluations/synthetic.json", policy_evaluation),
        ("authority/synthetic.json", authority),
        ("evidence/synthetic.json", evidence),
        ("reports/synthetic.json", report),
        ("practice/xai/readiness.json", xai_readiness),
    ]
    for kind in (
        "PASSPORT",
        "CUSTODY",
        "ATTESTATION",
        "GOVERNANCE",
        "SECURITY",
        "RUNTIME",
        "HISTORICAL",
        "PAYLOAD_INTEGRITY",
        "RECONCILIATION",
        "QUANTIZATION",
    ):
        linked = (
            _manifest_reference(manifests["config-reference.json"])
            if kind == "PAYLOAD_INTEGRITY"
            else None
        )
        objects.append(
            (
                f"integrations/{kind.lower()}.json",
                build_integration(evidence, kind, linked, identity_match=True),
            )
        )
    scenario_defs = _scenario_definitions()
    upstream = tuple(object_reference(value) for value in observations) + (
        object_reference(evidence),
        ObjectReference(
            schema_id=xai_readiness.schema_id,
            object_id=xai_readiness.readiness_id,
            object_digest=xai_readiness.readiness_digest,
        ),
    )
    scenarios = tuple(
        build_scenario(
            case_id,
            invariant,
            outcome.lower().replace("_", "."),
            (finding,),
            (upstream[index % len(upstream)],),
        )
        for index, (case_id, invariant, outcome, finding) in enumerate(scenario_defs)
    )
    objects.extend((f"scenarios/{value.case_id}.json", value) for value in scenarios)
    objects.append(("scenarios/catalog.json", build_catalog(scenarios)))
    objects.extend(_signed_examples(expectation, config_ref_asset, evidence))
    for relative, value in objects:
        _write(output_root / "tokenizer-configuration-parity" / relative, value)
    report_root = output_root / "reports" / "tokenizer-configuration-parity"
    report_root.mkdir(parents=True, exist_ok=True)
    atomic_write_text(report_root / "synthetic-parity-report.md", render_markdown(report))
    _write(report_root / "xai-tokenizer-configuration-readiness-case-study.json", xai_case)
    atomic_write_text(
        report_root / "xai-tokenizer-configuration-readiness-case-study.md",
        render_xai_case_study(xai_case, xai_readiness),
    )
    return _rebuild_index(output_root)


def _scenario_definitions() -> tuple[tuple[str, str, str, str], ...]:
    names = (
        (
            "exact-raw-configuration",
            "Raw bytes are identity-bearing.",
            "PASS",
            "EXACT_RAW_BYTES_FOR_SCOPE",
        ),
        (
            "canonical-json-key-order",
            "Canonical JSON is distinct from raw bytes.",
            "PASS",
            "CANONICAL_JSON_EQUAL_FOR_SCOPE",
        ),
        (
            "required-field-mismatch",
            "Required field mismatches remain visible.",
            "MISMATCH",
            "VALUE_MISMATCH",
        ),
        (
            "absent-versus-null",
            "Absent and explicit null are distinct.",
            "MISMATCH",
            "EXPLICIT_NULL_MISMATCH",
        ),
        (
            "policy-default-versus-absent",
            "Policy defaults are explicit and identity-bearing.",
            "MISMATCH",
            "DEFAULT_PROVENANCE_MISMATCH",
        ),
        (
            "integer-versus-decimal",
            "Typed integer and decimal values differ.",
            "MISMATCH",
            "VALUE_TYPE_MISMATCH",
        ),
        (
            "allowed-transformation",
            "Allowed differences retain raw mismatch.",
            "PASS",
            "EXPECTED_TRANSFORMATION_DIFFERENCE",
        ),
        (
            "unexpected-transformation",
            "Unlisted transformation differences fail.",
            "MISMATCH",
            "UNEXPECTED_TRANSFORMATION_DIFFERENCE",
        ),
        (
            "exact-vocabulary",
            "Token-to-ID and ID-to-token parity are separate.",
            "PASS",
            "TOKEN_TO_ID_MATCH",
        ),
        ("token-id-mismatch", "Token ID mismatch is preserved.", "MISMATCH", "TOKEN_ID_MISMATCH"),
        (
            "duplicate-token",
            "Duplicate token ambiguity is explicit.",
            "NOT_COMPARABLE",
            "DUPLICATE_TOKEN",
        ),
        ("duplicate-id", "Duplicate ID ambiguity is explicit.", "NOT_COMPARABLE", "DUPLICATE_ID"),
        (
            "nfc-versus-nfd",
            "Unicode code points are not normalized implicitly.",
            "MISMATCH",
            "UNICODE_NORMALIZATION_DISTINCTION",
        ),
        (
            "text-versus-bytes",
            "Unicode text and byte sequences differ.",
            "MISMATCH",
            "TOKEN_CONTENT_ENCODING_MISMATCH",
        ),
        ("merge-order", "BPE merge order is semantic.", "MISMATCH", "MERGE_ORDER_MISMATCH"),
        (
            "added-token-property",
            "Absent and false properties differ.",
            "MISMATCH",
            "ADDED_TOKEN_PROPERTY_MISMATCH",
        ),
        (
            "special-token-role-id",
            "Special role and ID remain independent.",
            "MISMATCH",
            "SPECIAL_TOKEN_ROLE_ID_MISMATCH",
        ),
        (
            "special-vocab-consistency",
            "Cross-asset special token consistency is explicit.",
            "MISMATCH",
            "INCONSISTENT_FOR_DECLARED_RULE",
        ),
        (
            "pipeline-order",
            "Pipeline component order is preserved.",
            "MISMATCH",
            "COMPONENT_ORDER_MISMATCH",
        ),
        (
            "opaque-pipeline",
            "Opaque components are not executed.",
            "NOT_EVALUATED",
            "OPAQUE_COMPONENT_PRESENT",
        ),
        (
            "exact-template-text",
            "Template text equality is content-scoped.",
            "PASS",
            "TEMPLATE_EXACT_CONTENT_MATCH",
        ),
        (
            "template-content-mismatch",
            "Templates are compared without rendering.",
            "MISMATCH",
            "TEMPLATE_CONTENT_MISMATCH",
        ),
        (
            "exact-encode-probes",
            "Supplied encode results can match exactly.",
            "PASS",
            "EXACT_FOR_DECLARED_PROBES",
        ),
        (
            "decode-probe-mismatch",
            "Supplied decode mismatch is preserved.",
            "MISMATCH",
            "MISMATCH_FOR_DECLARED_PROBES",
        ),
        (
            "finite-probe-scope",
            "Finite success remains probe-scoped.",
            "PARTIAL",
            "PARTIAL_PROBE_PARITY",
        ),
        (
            "digest-only-probe",
            "Digest-only input is not reproducible.",
            "NOT_COMPARABLE",
            "DIGEST_ONLY_NOT_REPRODUCIBLE",
        ),
        ("empty-scope", "Empty scope cannot pass vacuously.", "INVALID", "EMPTY_SCOPE_REJECTED"),
        (
            "missing-candidate",
            "Missing candidate content is not parity.",
            "NOT_EVALUATED",
            "PAYLOAD_CONTENT_UNAVAILABLE",
        ),
        (
            "phase6b-nonpayload",
            "Remote object IDs are not payload content.",
            "NOT_EVALUATED",
            "REMOTE_NON_PAYLOAD_IDENTITY_ONLY",
        ),
        (
            "phase6a-exact-binding",
            "Phase 6A is local byte authority.",
            "PASS",
            "EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE",
        ),
        (
            "phase6a-binding-mismatch",
            "Mismatched local bytes fail closed.",
            "INVALID",
            "PHASE6A_IDENTITY_MISMATCH",
        ),
        (
            "trusted-signer-no-publisher",
            "Signer trust does not create publisher authority.",
            "NOT_EVALUATED",
            "PUBLISHER_NOT_ESTABLISHED",
        ),
        (
            "model-a-authority-model-b",
            "Authority is subject scoped.",
            "INVALID",
            "AUTHORITY_SCOPE_MISMATCH",
        ),
        (
            "phase6c-independent",
            "Weight fidelity cannot establish tokenizer parity.",
            "NOT_EVALUATED",
            "QUANTIZATION_FIDELITY_INDEPENDENT",
        ),
        (
            "xai-readiness",
            "Pinned metadata records readiness without contents.",
            "NOT_EVALUATED",
            "XAI_REQUIRED_PAYLOAD_ASSETS_UNAVAILABLE",
        ),
        (
            "limit-exceeded",
            "Resource bounds fail without truncation.",
            "LIMIT_EXCEEDED",
            "LIMIT_EXCEEDED",
        ),
    )
    return names


def _canonical_id(value: dict[str, object]) -> str:
    schema = str(value.get("schema"))
    phase6d = {schema_id: identity[0] for schema_id, identity in IDENTITY_SPECS.items()}
    fields = {
        "omiv.observed-payload-manifest.v1": "manifest_id",
        "omiv.payload-hash-execution-record.v1": "execution_id",
        "omiv.xai-tokenizer-configuration-readiness.v1": "readiness_id",
        "omiv.xai-tokenizer-configuration-case-study.v1": "case_study_id",
        "omiv.signed-object-envelope.v1": "envelope_id",
        "omiv.signature-report.v1": "report_id",
        "omiv.trust-policy.v1": "policy_id",
        "omiv.trust-bundle.v1": "bundle_id",
        **phase6d,
    }
    field = fields.get(schema)
    if field is None or not isinstance(value.get(field), str):
        raise ValueError(f"generated Phase 6D object lacks canonical identity: {schema}")
    return str(value[field])


def _rebuild_index(root: Path) -> TokenizerConfigurationArtifactIndex:
    entries: list[TokenizerConfigurationArtifactIndexEntry] = []
    identities: set[str] = set()
    contents: set[str] = set()
    directories = (
        root / "tokenizer-configuration-parity",
        root / "reports" / "tokenizer-configuration-parity",
    )
    for directory in directories:
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.name == "artifact-index.json":
                continue
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".json":
                value = json.loads(raw)
                schema = str(value["schema"])
                canonical_id = _canonical_id(value)
            else:
                schema = "omiv.tokenizer-configuration-markdown-report.v1"
                canonical_id = "tokenizer_markdown_" + digest[:32]
            if digest in contents or canonical_id in identities:
                raise ValueError(
                    "duplicate Phase 6D generated content or canonical identity at " + relative
                )
            contents.add(digest)
            identities.add(canonical_id)
            entries.append(
                TokenizerConfigurationArtifactIndexEntry(
                    path=relative,
                    size=len(raw),
                    sha256=digest,
                    schema_id=schema,
                    canonical_id=canonical_id,
                )
            )
    index = TokenizerConfigurationArtifactIndex.model_validate(
        finalize_identity(
            {
                "schema": "omiv.tokenizer-configuration-artifact-index.v1",
                "entries": sorted(entries, key=lambda item: item.path.encode()),
                "total_size": sum(item.size for item in entries),
                "limitations": (
                    "External index excludes itself; artifacts contain bounded synthetic "
                    "metadata and no tokenizer or model payload.",
                ),
            },
            "index_id",
            "tokenizer_index_",
            "index_digest",
        )
    )
    _write(root / "tokenizer-configuration-parity" / "artifact-index.json", index)
    return index
