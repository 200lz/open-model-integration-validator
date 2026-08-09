"""Deterministic builders for Phase 6D canonical evidence objects."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, TypeVar

from pydantic import BaseModel

from omiv.runtime.models import ProductSubject
from omiv.tokenizer_parity.models import (
    AddedTokenObservation,
    AddedTokenRecord,
    ArtifactBinding,
    AuthorityDimension,
    AuthorityStatus,
    ChatTemplateObservation,
    ConfigurationFieldObservation,
    ConfigurationObservation,
    CoverageDimension,
    ExpectationAvailability,
    ExpectationMode,
    ExpectationReference,
    MergeRecord,
    MergeTableObservation,
    ObjectReference,
    OverallParityStatus,
    ParityFinding,
    ParityScope,
    ProbeKind,
    RequirementStatus,
    SpecialTokenObservation,
    SpecialTokenRecord,
    TokenContentEncoding,
    TokenizerAssetObservation,
    TokenizerConfigurationArtifactIndex,
    TokenizerConfigurationArtifactIndexEntry,
    TokenizerConfigurationAuthorityEvaluation,
    TokenizerConfigurationComparison,
    TokenizerConfigurationExecutionRecord,
    TokenizerConfigurationExpectation,
    TokenizerConfigurationInspectionPlan,
    TokenizerConfigurationIntegrationSummary,
    TokenizerConfigurationLimits,
    TokenizerConfigurationParityDeclaration,
    TokenizerConfigurationParityEvidence,
    TokenizerConfigurationPolicyEvaluation,
    TokenizerConfigurationReport,
    TokenizerConfigurationScenarioCatalog,
    TokenizerConfigurationScenarioResult,
    TokenizerPipelineComponent,
    TokenizerPipelineObservation,
    TokenizerProbeDefinition,
    TokenizerProbeExecutionRecord,
    TokenizerProbeResult,
    TokenizerProbeResultObservation,
    TokenizerProbeSetDefinition,
    VocabularyEntry,
    VocabularyObservation,
    finalize_identity,
    object_reference,
    verify_object_reference,
)

CanonicalModel = TypeVar("CanonicalModel", bound=BaseModel)


def _build(
    model: type[CanonicalModel],
    body: dict[str, Any],
    id_field: str,
    prefix: str,
    digest_field: str,
) -> CanonicalModel:
    return model.model_validate(finalize_identity(body, id_field, prefix, digest_field))


def build_expectation(
    subject: ProductSubject,
    *,
    scope: ParityScope,
    required_assets: Iterable[Any] = (),
    required_fields: Iterable[str] = (),
    required_special_roles: Iterable[Any] = (),
    required_probe_kinds: Iterable[ProbeKind] = (),
    authority_status: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    publisher: str | None = None,
) -> TokenizerConfigurationExpectation:
    body = {
        "schema": "omiv.tokenizer-configuration-expectation.v1",
        "subject": subject,
        "scope": scope,
        "required_assets": sorted(set(required_assets), key=lambda x: str(x)),
        "required_fields": sorted(set(required_fields), key=lambda x: x.encode()),
        "required_special_roles": sorted(set(required_special_roles), key=lambda x: str(x)),
        "required_probe_kinds": sorted(set(required_probe_kinds), key=lambda x: str(x)),
        "publisher": publisher,
        "authority_status": authority_status,
        "available_at": "NOT_RECORDED",
        "limitations": ["Expectation presence does not establish publisher authority."],
    }
    return _build(
        TokenizerConfigurationExpectation,
        body,
        "expectation_id",
        "tokenizer_expectation_",
        "expectation_digest",
    )


def build_declaration(
    subject: ProductSubject,
    expectation: TokenizerConfigurationExpectation | None,
    reference_artifacts: Iterable[ArtifactBinding],
    candidate_artifacts: Iterable[ArtifactBinding],
    *,
    mode: ExpectationMode = ExpectationMode.EMBEDDED_EXPECTATION,
    availability: ExpectationAvailability = ExpectationAvailability.FULL_EXPECTATION_AVAILABLE,
) -> TokenizerConfigurationParityDeclaration:
    expected_ref = ExpectationReference(
        reference=object_reference(expectation) if expectation is not None else None,
        object_supplied_and_verified=(
            expectation is not None
            and availability == ExpectationAvailability.FULL_EXPECTATION_AVAILABLE
        ),
        subject_id=subject.subject_id,
        provider=None,
        namespace=None,
        scope=expectation.scope if expectation is not None else ParityScope.PARTIAL_REFERENCE_SET,
        authority_status=expectation.authority_status
        if expectation is not None
        else AuthorityStatus.NOT_EVALUATED,
        availability=availability,
        limitations=("Digest-only or unavailable expectations cannot create parity.",),
    )
    body = {
        "schema": "omiv.tokenizer-configuration-parity-declaration.v1",
        "subject": subject,
        "scope": subject.scope,
        "expectation_mode": mode,
        "expectation": expected_ref,
        "reference_artifacts": list(reference_artifacts),
        "candidate_artifacts": list(candidate_artifacts),
        "provenance": "caller.declared",
        "declared_at": "NOT_RECORDED",
        "limitations": ["Declaration is not observation or proof of parity."],
    }
    return _build(
        TokenizerConfigurationParityDeclaration,
        body,
        "declaration_id",
        "tokenizer_declaration_",
        "declaration_digest",
    )


def build_plan(
    declaration: TokenizerConfigurationParityDeclaration,
    expectation: TokenizerConfigurationExpectation | None,
    supplied_inputs: Iterable[ObjectReference],
    selected_asset_paths: Iterable[str],
    *,
    scopes: Iterable[ParityScope],
    limits: TokenizerConfigurationLimits | None = None,
) -> TokenizerConfigurationInspectionPlan:
    if declaration.expectation.availability == ExpectationAvailability.FULL_EXPECTATION_AVAILABLE:
        if expectation is None or declaration.expectation.reference is None:
            raise ValueError("full expectation must be supplied to the inspection plan")
        verify_object_reference(declaration.expectation.reference, expectation)
        expectation_reference = object_reference(expectation)
    else:
        expectation_reference = None
    body = {
        "schema": "omiv.tokenizer-configuration-inspection-plan.v1",
        "subject": declaration.subject,
        "declaration": object_reference(declaration),
        "expectation": expectation_reference,
        "supplied_inputs": sorted(supplied_inputs, key=lambda x: (x.schema_id, x.object_id)),
        "selected_scopes": sorted(set(scopes), key=str),
        "selected_asset_paths": sorted(set(selected_asset_paths), key=lambda x: x.encode()),
        "limits": limits or TokenizerConfigurationLimits(),
        "network_use": "NONE",
        "tokenizer_execution": "NOT_PERFORMED",
        "template_execution": "NOT_PERFORMED",
        "requested_at": "NOT_RECORDED",
        "limitations": ["Plan contains no future execution or result identity."],
    }
    return _build(
        TokenizerConfigurationInspectionPlan, body, "plan_id", "tokenizer_plan_", "plan_digest"
    )


def build_execution(
    plan: TokenizerConfigurationInspectionPlan,
    supplied_inputs: Iterable[ObjectReference],
    *,
    counters: dict[str, int],
    status: str = "COMPLETED",
) -> TokenizerConfigurationExecutionRecord:
    body = {
        "schema": "omiv.tokenizer-configuration-execution-record.v1",
        "subject": plan.subject,
        "plan": object_reference(plan),
        "supplied_inputs": sorted(supplied_inputs, key=lambda x: (x.schema_id, x.object_id)),
        "tool_identity": "omiv.phase6d.offline-inspector.v1",
        "completion_status": status,
        "counters": sorted(counters.items()),
        "failure_class": None,
        "time_context": "NOT_RECORDED",
        "network_requests": 0,
        "executed_tokenizers": 0,
        "rendered_templates": 0,
        "limitations": ["Execution record contains no resulting observation or evidence identity."],
    }
    return _build(
        TokenizerConfigurationExecutionRecord,
        body,
        "execution_id",
        "tokenizer_execution_",
        "execution_digest",
    )


def build_asset_observation(
    execution: TokenizerConfigurationExecutionRecord,
    artifact: ArtifactBinding,
    *,
    raw_sha256: str,
    raw_size: int,
    format_identifier: str,
    format_supported: bool,
    race_findings: Iterable[str] = (),
) -> TokenizerAssetObservation:
    body = {
        "schema": "omiv.tokenizer-asset-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "artifact": artifact,
        "raw_sha256": raw_sha256,
        "raw_size": raw_size,
        "format_identifier": format_identifier,
        "format_supported": format_supported,
        "content_executed": False,
        "race_findings": sorted(set(race_findings)),
        "limitations": ["Observed bytes were treated as non-executing data."],
    }
    return _build(
        TokenizerAssetObservation, body, "observation_id", "tokenizer_asset_", "observation_digest"
    )


def build_configuration_observation(
    execution: TokenizerConfigurationExecutionRecord,
    artifact: ArtifactBinding,
    *,
    raw_sha256: str,
    canonical_json_sha256: str,
    projection_sha256: str,
    fields: Iterable[ConfigurationFieldObservation],
    coverage: Iterable[CoverageDimension],
    race_findings: Iterable[str] = (),
) -> ConfigurationObservation:
    body = {
        "schema": "omiv.configuration-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "artifact": artifact,
        "raw_sha256": raw_sha256,
        "canonical_json_sha256": canonical_json_sha256,
        "projection_sha256": projection_sha256,
        "fields": sorted(fields, key=lambda x: x.field_path.encode()),
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "race_findings": sorted(set(race_findings)),
        "limitations": ["No framework or runtime defaults were applied implicitly."],
    }
    return _build(
        ConfigurationObservation,
        body,
        "observation_id",
        "config_observation_",
        "observation_digest",
    )


def build_vocabulary_observation(
    execution: TokenizerConfigurationExecutionRecord,
    asset: TokenizerAssetObservation,
    entries: Iterable[VocabularyEntry],
    coverage: Iterable[CoverageDimension],
) -> VocabularyObservation:
    values = tuple(entries)
    tokens = [e.token.model_dump_json() for e in values]
    ids = [e.token_id for e in values]
    duplicate_tokens = len(tokens) - len(set(tokens))
    duplicate_ids = len(ids) - len(set(ids))
    sparse = bool(ids) and sorted(set(ids)) != list(range(min(ids), max(ids) + 1))
    body = {
        "schema": "omiv.vocabulary-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "asset_observation": object_reference(asset),
        "entries": values,
        "record_count": len(values),
        "distinct_token_count": len(set(tokens)),
        "distinct_id_count": len(set(ids)),
        "maximum_token_id": max(ids) if ids else None,
        "max_id_plus_one": max(ids) + 1 if ids else None,
        "base_vocabulary_count": None,
        "added_token_count": None,
        "duplicate_token_count": duplicate_tokens,
        "duplicate_id_count": duplicate_ids,
        "sparse_ids_observed": sparse,
        "comparable": duplicate_tokens == 0 and duplicate_ids == 0,
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Sparse IDs are preserved and are not assumed invalid."],
    }
    return _build(
        VocabularyObservation,
        body,
        "observation_id",
        "vocabulary_observation_",
        "observation_digest",
    )


def build_merge_observation(
    execution: TokenizerConfigurationExecutionRecord,
    asset: TokenizerAssetObservation,
    records: Iterable[MergeRecord],
    coverage: Iterable[CoverageDimension],
    *,
    header: str | None,
    malformed_count: int = 0,
) -> MergeTableObservation:
    values = tuple(records)
    pairs = [(r.left.model_dump_json(), r.right.model_dump_json()) for r in values]
    duplicates = len(pairs) - len(set(pairs))
    body = {
        "schema": "omiv.merge-table-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "asset_observation": object_reference(asset),
        "format_identifier": "bpe.merges.text.v1",
        "header": header,
        "records": values,
        "duplicate_count": duplicates,
        "malformed_count": malformed_count,
        "comparable": duplicates == 0 and malformed_count == 0,
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Merge order is identity-bearing and was not reordered."],
    }
    return _build(
        MergeTableObservation, body, "observation_id", "merge_observation_", "observation_digest"
    )


def build_added_token_observation(
    execution: TokenizerConfigurationExecutionRecord,
    asset: TokenizerAssetObservation,
    records: Iterable[AddedTokenRecord],
    coverage: Iterable[CoverageDimension],
) -> AddedTokenObservation:
    body = {
        "schema": "omiv.added-token-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "asset_observation": object_reference(asset),
        "records": list(records),
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Absent token properties remain distinct from explicit false."],
    }
    return _build(
        AddedTokenObservation,
        body,
        "observation_id",
        "added_token_observation_",
        "observation_digest",
    )


def build_special_token_observation(
    execution: TokenizerConfigurationExecutionRecord,
    source_assets: Iterable[ObjectReference],
    records: Iterable[SpecialTokenRecord],
    consistency_findings: Iterable[ParityFinding],
    coverage: Iterable[CoverageDimension],
) -> SpecialTokenObservation:
    body = {
        "schema": "omiv.special-token-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "source_assets": sorted(source_assets, key=lambda x: (x.schema_id, x.object_id)),
        "records": list(records),
        "consistency_findings": sorted(consistency_findings, key=lambda x: (x.code, x.subject)),
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Special-token meaning was not inferred from token spelling."],
    }
    return _build(
        SpecialTokenObservation,
        body,
        "observation_id",
        "special_token_observation_",
        "observation_digest",
    )


def build_pipeline_observation(
    execution: TokenizerConfigurationExecutionRecord,
    asset: TokenizerAssetObservation,
    components: Iterable[TokenizerPipelineComponent],
    coverage: Iterable[CoverageDimension],
) -> TokenizerPipelineObservation:
    body = {
        "schema": "omiv.tokenizer-pipeline-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "asset_observation": object_reference(asset),
        "components": sorted(components, key=lambda x: x.position),
        "behavior_evaluated": False,
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Component implementations were not imported or executed."],
    }
    return _build(
        TokenizerPipelineObservation,
        body,
        "observation_id",
        "pipeline_observation_",
        "observation_digest",
    )


def build_template_observation(
    execution: TokenizerConfigurationExecutionRecord,
    asset: TokenizerAssetObservation,
    *,
    content_digest: str,
    content_size: int,
    language: str | None,
) -> ChatTemplateObservation:
    body = {
        "schema": "omiv.chat-template-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "asset_observation": object_reference(asset),
        "content_encoding": TokenContentEncoding.UNICODE_TEXT,
        "content_digest": content_digest,
        "template_language": language,
        "template_name": "synthetic-chat-template",
        "availability": asset.artifact.availability,
        "template_executed": False,
        "content_size": content_size,
        "limitations": ["Exact text identity does not establish rendering equivalence."],
    }
    return _build(
        ChatTemplateObservation,
        body,
        "observation_id",
        "template_observation_",
        "observation_digest",
    )


def build_probe_set(
    subject: ProductSubject, probes: Iterable[TokenizerProbeDefinition]
) -> TokenizerProbeSetDefinition:
    body = {
        "schema": "omiv.tokenizer-probe-set-definition.v1",
        "subject": subject,
        "scope": ParityScope.SELECTED_REQUIRED_PROBES,
        "probes": sorted(probes, key=lambda x: x.probe_id),
        "limits": TokenizerConfigurationLimits(),
        "limitations": ["Finite supplied probes cannot establish complete tokenizer equivalence."],
    }
    return _build(
        TokenizerProbeSetDefinition,
        body,
        "probe_set_id",
        "tokenizer_probe_set_",
        "probe_set_digest",
    )


def build_probe_execution(
    plan: TokenizerConfigurationInspectionPlan,
    probe_set: TokenizerProbeSetDefinition,
    tokenizer_identities: Iterable[ObjectReference],
) -> TokenizerProbeExecutionRecord:
    body = {
        "schema": "omiv.tokenizer-probe-execution-record.v1",
        "subject": plan.subject,
        "inspection_plan": object_reference(plan),
        "probe_set": object_reference(probe_set),
        "tokenizer_identities": sorted(
            tokenizer_identities, key=lambda x: (x.schema_id, x.object_id)
        ),
        "tool_identity": "omiv.synthetic.supplied-probe-adapter.v1",
        "completion_status": "COMPLETED",
        "time_context": "NOT_RECORDED",
        "execution_context": "offline.synthetic.supplied-results",
        "limitations": ["Execution record contains no resulting probe-result reference."],
    }
    return _build(
        TokenizerProbeExecutionRecord,
        body,
        "execution_id",
        "tokenizer_probe_execution_",
        "execution_digest",
    )


def build_probe_results(
    execution: TokenizerProbeExecutionRecord,
    probe_set: TokenizerProbeSetDefinition,
    results: Iterable[TokenizerProbeResult],
    coverage: Iterable[CoverageDimension],
) -> TokenizerProbeResultObservation:
    body = {
        "schema": "omiv.tokenizer-probe-result-observation.v1",
        "subject": execution.subject,
        "execution": object_reference(execution),
        "probe_set": object_reference(probe_set),
        "results": sorted(results, key=lambda x: x.probe_id),
        "coverage": sorted(coverage, key=lambda x: x.dimension),
        "limitations": ["Supplied results were compared without executing a tokenizer."],
    }
    return _build(
        TokenizerProbeResultObservation,
        body,
        "observation_id",
        "tokenizer_probe_results_",
        "observation_digest",
    )


def build_authority(
    subject: ProductSubject,
    *,
    trusted_signer: bool = True,
    publisher: bool = False,
    scope_match: bool = True,
) -> TokenizerConfigurationAuthorityEvaluation:
    signer = AuthorityStatus.ESTABLISHED if trusted_signer else AuthorityStatus.NOT_ESTABLISHED
    publisher_status = (
        AuthorityStatus.ESTABLISHED
        if publisher and scope_match
        else (AuthorityStatus.SCOPE_MISMATCH if publisher else AuthorityStatus.NOT_ESTABLISHED)
    )
    dimensions = (
        AuthorityDimension(
            purpose="observation.signing",
            signature_state="signature.valid" if trusted_signer else "signature.unavailable",
            signer_trust=signer,
            purpose_authority=signer,
            subject_scope=AuthorityStatus.ESTABLISHED
            if scope_match
            else AuthorityStatus.SCOPE_MISMATCH,
            detail="Signature and scope are evaluated independently.",
        ),
        AuthorityDimension(
            purpose="publisher.authorization",
            signature_state="signature.valid" if trusted_signer else "signature.unavailable",
            signer_trust=signer,
            purpose_authority=publisher_status,
            subject_scope=AuthorityStatus.ESTABLISHED
            if scope_match
            else AuthorityStatus.SCOPE_MISMATCH,
            detail="Trusted signing does not create publisher authority.",
        ),
    )
    body = {
        "schema": "omiv.tokenizer-configuration-authority-evaluation.v1",
        "subject": subject,
        "scope": subject.scope,
        "reference_expectation_authority": publisher_status,
        "source_publisher_authority": publisher_status,
        "candidate_publisher_authority": publisher_status,
        "transformation_authority": AuthorityStatus.NOT_ESTABLISHED,
        "observation_signer_authority": signer,
        "probe_executor_authority": AuthorityStatus.NOT_ESTABLISHED,
        "policy_authority": AuthorityStatus.NOT_ESTABLISHED,
        "dimensions": dimensions,
        "overall_status": publisher_status
        if publisher_status != AuthorityStatus.ESTABLISHED
        else AuthorityStatus.ESTABLISHED,
        "limitations": [
            "Signature validity, signer trust, purpose, publisher, and transformer "
            "authority remain separate."
        ],
    }
    return _build(
        TokenizerConfigurationAuthorityEvaluation,
        body,
        "authority_evaluation_id",
        "tokenizer_authority_",
        "authority_evaluation_digest",
    )


def build_evidence(
    comparison: TokenizerConfigurationComparison,
    policy: TokenizerConfigurationPolicyEvaluation,
    authority: TokenizerConfigurationAuthorityEvaluation,
) -> TokenizerConfigurationParityEvidence:
    passed = policy.result == RequirementStatus.POLICY_REQUIREMENT_SATISFIED
    status = (
        comparison.raw_status
        if passed
        else (
            OverallParityStatus.MISMATCH_FOR_DECLARED_SCOPE
            if policy.result == RequirementStatus.POLICY_REQUIREMENT_FAILED
            else OverallParityStatus.INDETERMINATE
        )
    )
    body = {
        "schema": "omiv.tokenizer-configuration-parity-evidence.v1",
        "subject": comparison.subject,
        "scope": comparison.scope,
        "comparison": object_reference(comparison),
        "policy_evaluation": object_reference(policy),
        "authority_evaluation": object_reference(authority),
        "overall_status": status,
        "coverage": comparison.coverage,
        "authority_status": authority.overall_status,
        "behavioral_equivalence": "NOT_ESTABLISHED",
        "runtime_compatibility": "NOT_ESTABLISHED",
        "security_status": "NOT_EVALUATED",
        "authenticity": "NOT_ESTABLISHED",
        "evaluated_at": "NOT_RECORDED",
        "limitations": [
            "Parity is scope-qualified and does not establish model behavior, safety, "
            "authenticity, or runtime compatibility."
        ],
    }
    return _build(
        TokenizerConfigurationParityEvidence,
        body,
        "evidence_id",
        "tokenizer_evidence_",
        "evidence_digest",
    )


def build_integration(
    evidence: TokenizerConfigurationParityEvidence,
    kind: str,
    linked: ObjectReference | None,
    *,
    identity_match: bool,
) -> TokenizerConfigurationIntegrationSummary:
    states = {
        "PASSPORT": "derived.summary.only",
        "CUSTODY": "append.only.reference",
        "ATTESTATION": "claim.not.parity.proof",
        "GOVERNANCE": "evidence.not.approval",
        "SECURITY": "security.pass.not.created",
        "RUNTIME": "expected.not.observed",
        "HISTORICAL": "time.not.recorded",
        "PAYLOAD_INTEGRITY": "phase6a.authoritative",
        "RECONCILIATION": "remote.metadata.not.payload",
        "QUANTIZATION": "weight.fidelity.independent",
    }
    body = {
        "schema": "omiv.tokenizer-configuration-integration-summary.v1",
        "subject": evidence.subject,
        "evidence": object_reference(evidence),
        "integration_kind": kind,
        "linked_object": linked,
        "identity_match": identity_match,
        "derived_state": states[kind] if identity_match else "identity.mismatch.not.reused",
        "creates_approval": False,
        "creates_security_pass": False,
        "creates_runtime_observation": False,
        "limitations": ["Cross-phase linkage preserves the original evidence boundary."],
    }
    return _build(
        TokenizerConfigurationIntegrationSummary,
        body,
        "integration_id",
        "tokenizer_integration_",
        "integration_digest",
    )


def build_report(
    evidence: TokenizerConfigurationParityEvidence,
    findings: Iterable[ParityFinding],
    *,
    limit: int = 64,
) -> TokenizerConfigurationReport:
    values = sorted(findings, key=lambda x: (x.code, x.subject, x.detail))
    included = values[:limit]
    body = {
        "schema": "omiv.tokenizer-configuration-report.v1",
        "subject": evidence.subject,
        "evidence": object_reference(evidence),
        "title": "OMIV Tokenizer and Configuration Parity Evidence",
        "overall_status": evidence.overall_status,
        "total_findings": len(values),
        "included_findings": len(included),
        "omitted_findings": len(values) - len(included),
        "inclusion_rule": "lexicographic.code.subject.detail",
        "truncation_status": "NOT_TRUNCATED"
        if len(values) <= limit
        else "DETERMINISTICALLY_TRUNCATED",
        "findings": included,
        "limitations": ["Report is derived and never feeds canonical evidence identity."],
    }
    return _build(
        TokenizerConfigurationReport, body, "report_id", "tokenizer_report_", "report_digest"
    )


def build_scenario(
    case_id: str,
    invariant: str,
    outcome: str,
    findings: Iterable[str],
    upstream: Iterable[ObjectReference],
) -> TokenizerConfigurationScenarioResult:
    body = {
        "schema": "omiv.tokenizer-configuration-scenario-result.v1",
        "case_id": case_id,
        "exercised_invariant": invariant,
        "outcome": outcome,
        "findings": sorted(set(findings)),
        "upstream_objects": sorted(upstream, key=lambda x: (x.schema_id, x.object_id)),
        "limitations": ["Synthetic scenario is not real model or tokenizer evidence."],
    }
    return _build(
        TokenizerConfigurationScenarioResult,
        body,
        "result_id",
        "tokenizer_scenario_",
        "result_digest",
    )


def build_catalog(
    results: Iterable[TokenizerConfigurationScenarioResult],
) -> TokenizerConfigurationScenarioCatalog:
    body = {
        "schema": "omiv.tokenizer-configuration-scenario-catalog.v1",
        "classification": (
            "COMPLETE_AS_PROVIDER_NEUTRAL_TOKENIZER_AND_CONFIGURATION_PARITY_"
            "EVIDENCE_FOUNDATION_WITH_EXPLICIT_FORMAT_PROBE_AND_RUNTIME_LIMITATIONS"
        ),
        "scenarios": sorted((object_reference(r) for r in results), key=lambda x: x.object_id),
        "limitations": [
            "Foundation supports declared exact-identity scopes; it does not establish "
            "behavioral equivalence."
        ],
    }
    return _build(
        TokenizerConfigurationScenarioCatalog,
        body,
        "catalog_id",
        "tokenizer_catalog_",
        "catalog_digest",
    )


def build_index(
    entries: Iterable[TokenizerConfigurationArtifactIndexEntry],
) -> TokenizerConfigurationArtifactIndex:
    values = sorted(entries, key=lambda x: x.path.encode())
    body = {
        "schema": "omiv.tokenizer-configuration-artifact-index.v1",
        "entries": values,
        "total_size": sum(e.size for e in values),
        "limitations": ["External artifact index excludes itself."],
    }
    return _build(
        TokenizerConfigurationArtifactIndex, body, "index_id", "tokenizer_index_", "index_digest"
    )
