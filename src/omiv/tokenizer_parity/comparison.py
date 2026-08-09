"""Provider-neutral structural, supplied-probe, and policy comparison logic."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.tokenizer_parity.building import _build
from omiv.tokenizer_parity.models import (
    AddedTokenObservation,
    ArtifactAvailability,
    AssetKind,
    AuthorityStatus,
    CanonicalValueType,
    ChatTemplateObservation,
    ConfigurationObservation,
    ConfigurationStatus,
    CoverageDimension,
    CrossAssetConsistencyResult,
    CrossAssetStatus,
    DimensionResult,
    FindingStatus,
    MergeTableObservation,
    ObjectReference,
    OverallParityStatus,
    ParityDimension,
    ParityFinding,
    ParityScope,
    PipelineComponentKind,
    PolicyRequirementResult,
    ProbeComparisonStatus,
    ProbeKind,
    RequirementStatus,
    SpecialTokenObservation,
    TokenizerConfigurationAuthorityEvaluation,
    TokenizerConfigurationComparison,
    TokenizerConfigurationExpectation,
    TokenizerConfigurationParityDeclaration,
    TokenizerConfigurationPolicy,
    TokenizerConfigurationPolicyEvaluation,
    TokenizerPipelineObservation,
    TokenizerProbeResultObservation,
    VocabularyCardinalityBasis,
    VocabularyObservation,
    object_reference,
)


def compare_configurations(
    reference: ConfigurationObservation,
    candidate: ConfigurationObservation,
    *,
    required_fields: Iterable[str],
    aliases: dict[str, str] | None = None,
    allowed_transformation_fields: set[str] | None = None,
) -> tuple[tuple[ParityFinding, ...], ConfigurationStatus, DimensionResult]:
    alias = aliases or {}
    allowed = allowed_transformation_fields or set()
    selected_fields = tuple(required_fields)
    ref = {field.field_path: field for field in reference.fields}
    cand = {field.field_path: field for field in candidate.fields}
    findings: list[ParityFinding] = []
    compared = 0
    mismatches = 0
    for field_path in sorted(set(selected_fields), key=lambda x: x.encode()):
        candidate_path = alias.get(field_path, field_path)
        left = ref.get(field_path)
        right = cand.get(candidate_path)
        if left is None:
            findings.append(
                _finding(
                    "FIELD_MISSING_FROM_REFERENCE",
                    ParityDimension.CONFIGURATION_FIELDS,
                    FindingStatus.INCOMPLETE,
                    field_path,
                    "Required field observation is absent from the reference projection.",
                )
            )
            mismatches += 1
            continue
        if right is None:
            findings.append(
                _finding(
                    "FIELD_MISSING_FROM_CANDIDATE",
                    ParityDimension.CONFIGURATION_FIELDS,
                    FindingStatus.INCOMPLETE,
                    candidate_path,
                    "Required field observation is absent from the candidate projection.",
                )
            )
            mismatches += 1
            continue
        compared += 1
        field_findings = _compare_field(left, right)
        if field_findings:
            if field_path in allowed:
                findings.append(
                    _finding(
                        "EXPECTED_TRANSFORMATION_DIFFERENCE",
                        ParityDimension.CONFIGURATION_FIELDS,
                        FindingStatus.ALLOWED_DIFFERENCE,
                        field_path,
                        "Original typed mismatch is retained and explicitly allowed "
                        "by an identity-bearing rule.",
                    )
                )
                findings.extend(field_findings)
            else:
                findings.extend(field_findings)
                mismatches += 1
        else:
            findings.append(
                _finding(
                    "FIELD_PATH_MATCH",
                    ParityDimension.CONFIGURATION_FIELDS,
                    FindingStatus.OBSERVED,
                    field_path,
                    "Presence, type, and canonical value match for the selected field.",
                )
            )
    if not selected_fields:
        status = ConfigurationStatus.INCOMPLETE_CONFIGURATION_EVIDENCE
        findings.append(
            _finding(
                "EMPTY_SCOPE_REJECTED",
                ParityDimension.COVERAGE,
                FindingStatus.INCOMPLETE,
                "configuration",
                "An empty required-field scope cannot pass.",
            )
        )
    elif mismatches:
        status = ConfigurationStatus.FIELD_MISMATCH
    elif reference.raw_sha256 == candidate.raw_sha256:
        status = ConfigurationStatus.EXACT_RAW_BYTES_FOR_SCOPE
    elif reference.canonical_json_sha256 == candidate.canonical_json_sha256:
        status = ConfigurationStatus.CANONICAL_JSON_EQUAL_FOR_SCOPE
    else:
        status = ConfigurationStatus.FIELD_PARITY_FOR_DECLARED_SCOPE
    dimension = DimensionResult(
        dimension=ParityDimension.CONFIGURATION_FIELDS,
        status=FindingStatus.MISMATCH
        if mismatches
        else (FindingStatus.OBSERVED if compared else FindingStatus.INCOMPLETE),
        compared_count=compared,
        mismatch_count=mismatches,
        limitations=("Raw bytes, canonical JSON, and field projection parity remain distinct.",),
    )
    return tuple(findings), status, dimension


def compare_vocabularies(
    reference: VocabularyObservation, candidate: VocabularyObservation
) -> tuple[tuple[ParityFinding, ...], tuple[DimensionResult, DimensionResult]]:
    findings: list[ParityFinding] = []
    if not reference.comparable or not candidate.comparable:
        findings.append(
            _finding(
                "AMBIGUOUS_VOCABULARY",
                ParityDimension.VOCABULARY_TOKEN_TO_ID,
                FindingStatus.NOT_COMPARABLE,
                "vocabulary",
                "Duplicate token or ID makes bidirectional comparison unsound.",
            )
        )
        result = DimensionResult(
            dimension=ParityDimension.VOCABULARY_TOKEN_TO_ID,
            status=FindingStatus.NOT_COMPARABLE,
            compared_count=0,
            mismatch_count=1,
            limitations=("Ambiguous vocabulary was not guessed.",),
        )
        inverse = result.model_copy(update={"dimension": ParityDimension.VOCABULARY_ID_TO_TOKEN})
        return tuple(findings), (result, inverse)
    ref_token = {_token_key(e.token): e.token_id for e in reference.entries}
    cand_token = {_token_key(e.token): e.token_id for e in candidate.entries}
    mismatches = 0
    for token in sorted(set(ref_token) | set(cand_token)):
        if token not in ref_token:
            findings.append(
                _finding(
                    "EXTRA_CANDIDATE_TOKEN",
                    ParityDimension.VOCABULARY_TOKEN_TO_ID,
                    FindingStatus.MISMATCH,
                    token,
                    "Candidate contains a token outside the declared reference scope.",
                )
            )
            mismatches += 1
        elif token not in cand_token:
            findings.append(
                _finding(
                    "TOKEN_MISSING_FROM_CANDIDATE",
                    ParityDimension.VOCABULARY_TOKEN_TO_ID,
                    FindingStatus.MISMATCH,
                    token,
                    "Reference token is absent from candidate.",
                )
            )
            mismatches += 1
        elif ref_token[token] != cand_token[token]:
            findings.append(
                _finding(
                    "TOKEN_ID_MISMATCH",
                    ParityDimension.VOCABULARY_TOKEN_TO_ID,
                    FindingStatus.MISMATCH,
                    token,
                    f"Reference ID {ref_token[token]} differs from candidate ID "
                    f"{cand_token[token]}.",
                )
            )
            mismatches += 1
        else:
            findings.append(
                _finding(
                    "TOKEN_TO_ID_MATCH",
                    ParityDimension.VOCABULARY_TOKEN_TO_ID,
                    FindingStatus.OBSERVED,
                    token,
                    "Exact token content encoding maps to the same token ID.",
                )
            )
    ref_id = {e.token_id: _token_key(e.token) for e in reference.entries}
    cand_id = {e.token_id: _token_key(e.token) for e in candidate.entries}
    inverse_mismatches = sum(ref_id.get(i) != cand_id.get(i) for i in set(ref_id) | set(cand_id))
    return tuple(findings), (
        DimensionResult(
            dimension=ParityDimension.VOCABULARY_TOKEN_TO_ID,
            status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
            compared_count=len(set(ref_token) | set(cand_token)),
            mismatch_count=mismatches,
            limitations=(),
        ),
        DimensionResult(
            dimension=ParityDimension.VOCABULARY_ID_TO_TOKEN,
            status=FindingStatus.MISMATCH if inverse_mismatches else FindingStatus.OBSERVED,
            compared_count=len(set(ref_id) | set(cand_id)),
            mismatch_count=inverse_mismatches,
            limitations=("Sparse IDs are compared exactly and are not densified.",),
        ),
    )


def compare_merges(
    reference: MergeTableObservation, candidate: MergeTableObservation
) -> tuple[tuple[ParityFinding, ...], DimensionResult]:
    if not reference.comparable or not candidate.comparable:
        finding = _finding(
            "MERGE_TABLE_NOT_COMPARABLE",
            ParityDimension.MERGE_ORDER,
            FindingStatus.NOT_COMPARABLE,
            "merge-table",
            "Malformed or duplicate merge records prevent sound comparison.",
        )
        return (finding,), DimensionResult(
            dimension=ParityDimension.MERGE_ORDER,
            status=FindingStatus.NOT_COMPARABLE,
            compared_count=0,
            mismatch_count=1,
            limitations=(),
        )
    left = [(_token_key(r.left), _token_key(r.right)) for r in reference.records]
    right = [(_token_key(r.left), _token_key(r.right)) for r in candidate.records]
    findings: list[ParityFinding] = []
    mismatches = 0
    for index in range(max(len(left), len(right))):
        if index >= len(left):
            code, detail = "MERGE_EXTRA", "Candidate has an additional merge record."
        elif index >= len(right):
            code, detail = "MERGE_MISSING", "Candidate is missing a reference merge record."
        elif left[index] != right[index] and left[index] in right:
            code, detail = "MERGE_ORDER_MISMATCH", "Merge operands exist but at a different rank."
        elif left[index] != right[index]:
            code, detail = "MERGE_OPERAND_MISMATCH", "Merge operands differ at this rank."
        else:
            findings.append(
                _finding(
                    "MERGE_RECORD_MATCH",
                    ParityDimension.MERGE_ORDER,
                    FindingStatus.OBSERVED,
                    str(index),
                    "Merge operands and rank match.",
                )
            )
            continue
        mismatches += 1
        findings.append(
            _finding(code, ParityDimension.MERGE_ORDER, FindingStatus.MISMATCH, str(index), detail)
        )
    return tuple(findings), DimensionResult(
        dimension=ParityDimension.MERGE_ORDER,
        status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
        compared_count=max(len(left), len(right)),
        mismatch_count=mismatches,
        limitations=("Merge order is semantic and was not sorted before comparison.",),
    )


def compare_added_tokens(
    reference: AddedTokenObservation, candidate: AddedTokenObservation
) -> tuple[tuple[ParityFinding, ...], DimensionResult]:
    left = {_token_key(r.content): r for r in reference.records}
    right = {_token_key(r.content): r for r in candidate.records}
    fields = (
        "token_id",
        "token_id_presence",
        "special",
        "single_word",
        "lstrip",
        "rstrip",
        "normalized",
        "property_presence",
    )
    findings: list[ParityFinding] = []
    mismatches = 0
    for token in sorted(set(left) | set(right)):
        if token not in left or token not in right:
            findings.append(
                _finding(
                    "ADDED_TOKEN_MISSING",
                    ParityDimension.ADDED_TOKEN_PROPERTIES,
                    FindingStatus.MISMATCH,
                    token,
                    "Added token is missing from one side.",
                )
            )
            mismatches += 1
            continue
        changed = [
            name for name in fields if getattr(left[token], name) != getattr(right[token], name)
        ]
        if changed:
            findings.append(
                _finding(
                    "ADDED_TOKEN_PROPERTY_MISMATCH",
                    ParityDimension.ADDED_TOKEN_PROPERTIES,
                    FindingStatus.MISMATCH,
                    token,
                    "Differing properties: " + ",".join(changed),
                )
            )
            mismatches += 1
        else:
            findings.append(
                _finding(
                    "ADDED_TOKEN_PROPERTIES_MATCH",
                    ParityDimension.ADDED_TOKEN_PROPERTIES,
                    FindingStatus.OBSERVED,
                    token,
                    "All explicitly present added-token properties match.",
                )
            )
    return tuple(findings), DimensionResult(
        dimension=ParityDimension.ADDED_TOKEN_PROPERTIES,
        status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
        compared_count=len(set(left) | set(right)),
        mismatch_count=mismatches,
        limitations=("Absent property and explicit false remain distinct.",),
    )


def compare_special_tokens(
    reference: SpecialTokenObservation, candidate: SpecialTokenObservation
) -> tuple[tuple[ParityFinding, ...], DimensionResult]:
    left = {r.role: r for r in reference.records}
    right = {r.role: r for r in candidate.records}
    findings: list[ParityFinding] = []
    mismatches = 0
    for role in sorted(set(left) | set(right), key=str):
        if role not in left or role not in right:
            findings.append(
                _finding(
                    "SPECIAL_TOKEN_ROLE_MISMATCH",
                    ParityDimension.SPECIAL_TOKEN_ROLES,
                    FindingStatus.MISMATCH,
                    str(role),
                    "Special-token role is absent from one side.",
                )
            )
            mismatches += 1
            continue
        a, b = left[role], right[role]
        if (a.content, a.content_presence, a.token_id, a.token_id_presence) != (
            b.content,
            b.content_presence,
            b.token_id,
            b.token_id_presence,
        ):
            findings.append(
                _finding(
                    "SPECIAL_TOKEN_ROLE_ID_MISMATCH",
                    ParityDimension.SPECIAL_TOKEN_ROLES,
                    FindingStatus.MISMATCH,
                    str(role),
                    "Role content, ID, or presence state differs.",
                )
            )
            mismatches += 1
        else:
            findings.append(
                _finding(
                    "SPECIAL_TOKEN_ROLE_MATCH",
                    ParityDimension.SPECIAL_TOKEN_ROLES,
                    FindingStatus.OBSERVED,
                    str(role),
                    "Role, content, ID, and presence match.",
                )
            )
    return tuple(findings), DimensionResult(
        dimension=ParityDimension.SPECIAL_TOKEN_ROLES,
        status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
        compared_count=len(set(left) | set(right)),
        mismatch_count=mismatches,
        limitations=("Token spelling does not infer role meaning.",),
    )


def compare_pipelines(
    reference: TokenizerPipelineObservation, candidate: TokenizerPipelineObservation
) -> tuple[tuple[ParityFinding, ...], DimensionResult]:
    findings: list[ParityFinding] = []
    mismatches = 0
    for index in range(max(len(reference.components), len(candidate.components))):
        if index >= len(reference.components):
            code, detail = "COMPONENT_EXTRA", "Candidate has an extra component."
        elif index >= len(candidate.components):
            code, detail = "COMPONENT_MISSING", "Candidate is missing a component."
        else:
            left, right = reference.components[index], candidate.components[index]
            if left.position != right.position:
                code, detail = "COMPONENT_ORDER_MISMATCH", "Component positions differ."
            elif (
                left.component_kind != right.component_kind
                or left.type_identifier != right.type_identifier
            ):
                code, detail = "COMPONENT_TYPE_MISMATCH", "Component kind or declared type differs."
            elif left.parameter_digest != right.parameter_digest:
                code, detail = (
                    "COMPONENT_PARAMETER_MISMATCH",
                    "Canonical component parameter digest differs.",
                )
            elif "OPAQUE_COMPONENT" in {
                left.support_state.value,
                right.support_state.value,
            }:
                findings.append(
                    _finding(
                        "OPAQUE_COMPONENT_PRESENT",
                        ParityDimension.TOKENIZER_PIPELINE,
                        FindingStatus.NOT_EVALUATED,
                        str(index),
                        "Opaque component behavior was not inferred.",
                    )
                )
                continue
            else:
                findings.append(
                    _finding(
                        "PIPELINE_STRUCTURE_MATCH",
                        ParityDimension.TOKENIZER_PIPELINE,
                        FindingStatus.OBSERVED,
                        str(index),
                        "Ordered structural component descriptor matches.",
                    )
                )
                continue
        mismatches += 1
        findings.append(
            _finding(
                code, ParityDimension.TOKENIZER_PIPELINE, FindingStatus.MISMATCH, str(index), detail
            )
        )
    findings.append(
        _finding(
            "PIPELINE_NOT_BEHAVIORALLY_EVALUATED",
            ParityDimension.TOKENIZER_PIPELINE,
            FindingStatus.NOT_EVALUATED,
            "pipeline",
            "No component implementation was imported or executed.",
        )
    )
    return tuple(findings), DimensionResult(
        dimension=ParityDimension.TOKENIZER_PIPELINE,
        status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
        compared_count=max(len(reference.components), len(candidate.components)),
        mismatch_count=mismatches,
        limitations=("Structural pipeline parity is not behavioral equivalence.",),
    )


def compare_templates(
    reference: ChatTemplateObservation, candidate: ChatTemplateObservation
) -> tuple[tuple[ParityFinding, ...], DimensionResult]:
    mismatches = 0
    findings: list[ParityFinding] = []
    if reference.template_language != candidate.template_language:
        findings.append(
            _finding(
                "TEMPLATE_LANGUAGE_MISMATCH",
                ParityDimension.CHAT_TEMPLATE,
                FindingStatus.MISMATCH,
                "template",
                "Declared template language differs.",
            )
        )
        mismatches += 1
    if reference.content_digest != candidate.content_digest:
        findings.append(
            _finding(
                "TEMPLATE_CONTENT_MISMATCH",
                ParityDimension.CHAT_TEMPLATE,
                FindingStatus.MISMATCH,
                "template",
                "Exact template content digest differs.",
            )
        )
        mismatches += 1
    else:
        findings.append(
            _finding(
                "TEMPLATE_EXACT_CONTENT_MATCH",
                ParityDimension.CHAT_TEMPLATE,
                FindingStatus.OBSERVED,
                "template",
                "Exact supplied template text bytes match.",
            )
        )
    findings.append(
        _finding(
            "TEMPLATE_PRESENT_NOT_EXECUTED",
            ParityDimension.CHAT_TEMPLATE,
            FindingStatus.NOT_EVALUATED,
            "template",
            "Template was treated as untrusted data and not rendered.",
        )
    )
    return tuple(findings), DimensionResult(
        dimension=ParityDimension.CHAT_TEMPLATE,
        status=FindingStatus.MISMATCH if mismatches else FindingStatus.OBSERVED,
        compared_count=1,
        mismatch_count=mismatches,
        limitations=("Text equality does not establish runtime render equivalence.",),
    )


def compare_probe_results(
    reference: TokenizerProbeResultObservation, candidate: TokenizerProbeResultObservation
) -> tuple[tuple[ParityFinding, ...], ProbeComparisonStatus, tuple[DimensionResult, ...]]:
    left = {r.probe_id: r for r in reference.results}
    right = {r.probe_id: r for r in candidate.results}
    findings: list[ParityFinding] = []
    counts = {
        ParityDimension.ENCODE_PROBES: [0, 0],
        ParityDimension.DECODE_PROBES: [0, 0],
        ParityDimension.TEMPLATE_RENDER_PROBES: [0, 0],
    }
    mismatch = 0
    digest_only = False
    for probe_id in sorted(set(left) | set(right)):
        if probe_id not in left or probe_id not in right:
            findings.append(
                _finding(
                    "PROBE_RESULT_UNAVAILABLE",
                    ParityDimension.ENCODE_PROBES,
                    FindingStatus.INCOMPLETE,
                    probe_id,
                    "Supplied result is absent from one side.",
                )
            )
            mismatch += 1
            continue
        a, b = left[probe_id], right[probe_id]
        if a.probe_kind != b.probe_kind:
            findings.append(
                _finding(
                    "PROBE_KIND_MISMATCH",
                    ParityDimension.ENCODE_PROBES,
                    FindingStatus.MISMATCH,
                    probe_id,
                    "Supplied probe-result kinds differ.",
                )
            )
            mismatch += 1
            continue
        dimension = {
            ProbeKind.DECODE_TOKEN_IDS_TO_TEXT: ParityDimension.DECODE_PROBES,
            ProbeKind.CHAT_TEMPLATE_RENDER: ParityDimension.TEMPLATE_RENDER_PROBES,
        }.get(a.probe_kind, ParityDimension.ENCODE_PROBES)
        counts[dimension][0] += 1
        if (
            a.status == ProbeComparisonStatus.DIGEST_ONLY_NOT_REPRODUCIBLE
            or b.status == ProbeComparisonStatus.DIGEST_ONLY_NOT_REPRODUCIBLE
        ):
            digest_only = True
            findings.append(
                _finding(
                    "DIGEST_ONLY_NOT_REPRODUCIBLE",
                    dimension,
                    FindingStatus.NOT_COMPARABLE,
                    probe_id,
                    "Digest-only input cannot be independently reproduced.",
                )
            )
            continue
        if a != b:
            counts[dimension][1] += 1
            mismatch += 1
            findings.append(
                _finding(
                    "PROBE_OUTPUT_MISMATCH",
                    dimension,
                    FindingStatus.MISMATCH,
                    probe_id,
                    "Supplied probe outputs differ.",
                )
            )
        else:
            findings.append(
                _finding(
                    "PROBE_OUTPUT_EXACT",
                    dimension,
                    FindingStatus.OBSERVED,
                    probe_id,
                    "Supplied probe outputs match exactly.",
                )
            )
    if mismatch:
        status = ProbeComparisonStatus.MISMATCH_FOR_DECLARED_PROBES
    elif digest_only:
        status = ProbeComparisonStatus.DIGEST_ONLY_NOT_REPRODUCIBLE
    elif left:
        status = ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES
    else:
        status = ProbeComparisonStatus.PROBE_RESULT_UNAVAILABLE
    dimensions = tuple(
        DimensionResult(
            dimension=d,
            status=FindingStatus.MISMATCH
            if m
            else (FindingStatus.OBSERVED if n else FindingStatus.NOT_EVALUATED),
            compared_count=n,
            mismatch_count=m,
            limitations=("Finite probe success remains selected-probe scope.",),
        )
        for d, (n, m) in counts.items()
    )
    return tuple(findings), status, dimensions


def build_comparison(
    declaration: TokenizerConfigurationParityDeclaration,
    expectation: TokenizerConfigurationExpectation | None,
    observations: Iterable[ObjectReference],
    probe_results: Iterable[ObjectReference],
    findings: Iterable[ParityFinding],
    dimensions: Iterable[DimensionResult],
    coverage: Iterable[CoverageDimension],
    *,
    configuration_status: ConfigurationStatus,
    probe_status: ProbeComparisonStatus,
    scope: ParityScope,
    cross_asset: Iterable[CrossAssetConsistencyResult] = (),
) -> TokenizerConfigurationComparison:
    values = tuple(sorted(findings, key=lambda x: (x.code, x.subject, x.detail)))
    cover = tuple(sorted(coverage, key=lambda x: x.dimension))
    mismatch = any(f.status == FindingStatus.MISMATCH for f in values)
    incomplete = any(
        f.status in {FindingStatus.INCOMPLETE, FindingStatus.NOT_COMPARABLE, FindingStatus.INVALID}
        for f in values
    )
    complete_coverage = bool(cover) and all(
        c.denominator not in {None, 0} and c.numerator == c.denominator for c in cover
    )
    if mismatch:
        raw = OverallParityStatus.MISMATCH_FOR_DECLARED_SCOPE
    elif scope == ParityScope.SELECTED_REQUIRED_PROBES:
        raw = OverallParityStatus.PARTIAL_PARITY
    elif incomplete or not complete_coverage or expectation is None:
        raw = OverallParityStatus.INDETERMINATE
    else:
        raw = OverallParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE
    body = {
        "schema": "omiv.tokenizer-configuration-comparison.v1",
        "subject": declaration.subject,
        "declaration": object_reference(declaration),
        "expectation": object_reference(expectation) if expectation is not None else None,
        "observations": sorted(observations, key=lambda x: (x.schema_id, x.object_id)),
        "probe_results": sorted(probe_results, key=lambda x: x.object_id),
        "scope": scope,
        "configuration_status": configuration_status,
        "probe_status": probe_status,
        "dimension_results": sorted(dimensions, key=lambda x: x.dimension.value),
        "cross_asset_results": sorted(cross_asset, key=lambda x: x.rule_id),
        "findings": values,
        "coverage": cover,
        "raw_status": raw,
        "limitations": [
            "Finite probes, metadata, or partial scopes cannot create complete tokenizer "
            "equivalence."
        ],
    }
    return _build(
        TokenizerConfigurationComparison,
        body,
        "comparison_id",
        "tokenizer_comparison_",
        "comparison_digest",
    )


def build_policy(
    subject: Any,
    *,
    scope: ParityScope,
    required_assets: Iterable[AssetKind],
    required_fields: Iterable[str],
    required_special_roles: Iterable[Any] = (),
    required_pipeline_components: Iterable[PipelineComponentKind] = (),
    required_probe_kinds: Iterable[Any] = (),
    require_authority: bool = False,
) -> TokenizerConfigurationPolicy:
    body = {
        "schema": "omiv.tokenizer-configuration-policy.v1",
        "subject": subject,
        "scope": scope,
        "required_identity": ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE,
        "required_assets": sorted(set(required_assets), key=str),
        "required_fields": sorted(set(required_fields)),
        "required_special_roles": sorted(set(required_special_roles), key=str),
        "required_pipeline_components": sorted(set(required_pipeline_components), key=str),
        "required_probe_kinds": sorted(set(required_probe_kinds), key=str),
        "alias_rules": [],
        "transformation_rules": [],
        "minimum_vocabulary_coverage": "1",
        "minimum_probe_coverage": "1",
        "allow_duplicate_token": False,
        "allow_duplicate_id": False,
        "require_merge_order": True,
        "opaque_component_behavior": "NOT_EVALUATED",
        "require_chat_template": False,
        "digest_only_probes_acceptable": False,
        "require_authority": require_authority,
        "missing_input_behavior": "NOT_EVALUATED",
        "unsupported_format_behavior": "NOT_EVALUATED",
        "evaluation_context": subject.scope,
        "limitations": [
            "Policy PASS remains scope-qualified and cannot create governance approval."
        ],
    }
    return _build(
        TokenizerConfigurationPolicy, body, "policy_id", "tokenizer_policy_", "policy_digest"
    )


def evaluate_policy(
    comparison: TokenizerConfigurationComparison,
    policy: TokenizerConfigurationPolicy,
    authority: TokenizerConfigurationAuthorityEvaluation | None,
) -> TokenizerConfigurationPolicyEvaluation:
    requirements: list[PolicyRequirementResult] = []

    def add(name: str, ok: bool | None, observed: str, required: str, detail: str) -> None:
        status = (
            RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED
            if ok is None
            else (
                RequirementStatus.POLICY_REQUIREMENT_SATISFIED
                if ok
                else RequirementStatus.POLICY_REQUIREMENT_FAILED
            )
        )
        requirements.append(
            PolicyRequirementResult(
                requirement=name, status=status, observed=observed, required=required, detail=detail
            )
        )

    add(
        "declared.scope.parity",
        comparison.raw_status == OverallParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE,
        comparison.raw_status.value,
        OverallParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE.value,
        "Raw comparison must establish exact scope-qualified parity.",
    )
    for coverage in comparison.coverage:
        ok = (
            None
            if coverage.denominator is None
            else coverage.denominator > 0 and coverage.numerator == coverage.denominator
        )
        add(
            "coverage." + coverage.dimension.lower(),
            ok,
            f"{coverage.numerator}/"
            f"{coverage.denominator if coverage.denominator is not None else 'UNKNOWN'}",
            "complete.nonempty",
            "Coverage denominator must be available, nonzero, and complete.",
        )
    if policy.required_probe_kinds:
        add(
            "required.probes",
            comparison.probe_status == ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES,
            comparison.probe_status.value,
            ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES.value,
            "Every explicitly required supplied probe must match, without creating "
            "complete-model equivalence.",
        )
    if policy.require_authority:
        add(
            "required.authority",
            authority is not None and authority.overall_status == AuthorityStatus.ESTABLISHED,
            authority.overall_status.value if authority else "NOT_SUPPLIED",
            AuthorityStatus.ESTABLISHED.value,
            "Authority is independent of signature validity and structural usefulness.",
        )
    failed = any(r.status == RequirementStatus.POLICY_REQUIREMENT_FAILED for r in requirements)
    not_evaluated = any(
        r.status == RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED for r in requirements
    )
    result = (
        RequirementStatus.POLICY_REQUIREMENT_FAILED
        if failed
        else (
            RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED
            if not_evaluated
            else RequirementStatus.POLICY_REQUIREMENT_SATISFIED
        )
    )
    body = {
        "schema": "omiv.tokenizer-configuration-policy-evaluation.v1",
        "subject": comparison.subject,
        "comparison": object_reference(comparison),
        "policy": object_reference(policy),
        "authority": object_reference(authority) if authority is not None else None,
        "requirements": sorted(requirements, key=lambda x: x.requirement),
        "result": result,
        "evaluated_at": "NOT_RECORDED",
        "limitations": [
            "All failed policy dimensions are retained; evaluation does not stop at the "
            "first failure."
        ],
    }
    return _build(
        TokenizerConfigurationPolicyEvaluation,
        body,
        "evaluation_id",
        "tokenizer_policy_evaluation_",
        "evaluation_digest",
    )


def cross_asset_rule(
    rule_id: str, status: Any, inputs: Iterable[ObjectReference], detail: str
) -> CrossAssetConsistencyResult:
    return CrossAssetConsistencyResult(
        rule_id=rule_id,
        status=status,
        inputs=tuple(sorted(inputs, key=lambda x: x.object_id)),
        detail=detail,
    )


def evaluate_vocabulary_size_rule(
    configuration: ConfigurationObservation,
    vocabulary: VocabularyObservation,
    *,
    field_path: str,
    basis: VocabularyCardinalityBasis,
) -> CrossAssetConsistencyResult:
    """Evaluate an explicit cardinality basis without guessing framework semantics."""
    field = next((item for item in configuration.fields if item.field_path == field_path), None)
    observed = vocabulary_cardinality(vocabulary, basis)
    inputs = (object_reference(configuration), object_reference(vocabulary))
    if (
        field is None
        or field.value is None
        or field.value.value_type != CanonicalValueType.INTEGER
        or field.value.integer_value is None
    ):
        return cross_asset_rule(
            f"config.vocabulary-size.{basis.value.lower()}",
            CrossAssetStatus.REQUIRED_INPUT_MISSING,
            inputs,
            f"Field {field_path} is unavailable or is not an exact integer.",
        )
    if observed is None:
        return cross_asset_rule(
            f"config.vocabulary-size.{basis.value.lower()}",
            CrossAssetStatus.NOT_EVALUATED,
            inputs,
            f"Cardinality basis {basis.value} is unavailable and was not guessed.",
        )
    status = (
        CrossAssetStatus.CONSISTENT_FOR_DECLARED_RULE
        if field.value.integer_value == observed
        else CrossAssetStatus.INCONSISTENT_FOR_DECLARED_RULE
    )
    return cross_asset_rule(
        f"config.vocabulary-size.{basis.value.lower()}",
        status,
        inputs,
        f"Explicit {basis.value} basis compared configuration value "
        f"{field.value.integer_value} with observed cardinality {observed}.",
    )


def vocabulary_cardinality(
    observation: VocabularyObservation, basis: VocabularyCardinalityBasis
) -> int | None:
    values = {
        VocabularyCardinalityBasis.RECORD_COUNT: observation.record_count,
        VocabularyCardinalityBasis.DISTINCT_TOKEN_COUNT: observation.distinct_token_count,
        VocabularyCardinalityBasis.DISTINCT_ID_COUNT: observation.distinct_id_count,
        VocabularyCardinalityBasis.MAX_ID_PLUS_ONE: observation.max_id_plus_one,
        VocabularyCardinalityBasis.BASE_VOCABULARY_COUNT: observation.base_vocabulary_count,
        VocabularyCardinalityBasis.TOTAL_WITH_ADDED_TOKENS: (
            observation.base_vocabulary_count + observation.added_token_count
            if observation.base_vocabulary_count is not None
            and observation.added_token_count is not None
            else None
        ),
    }
    return values[basis]


def _compare_field(left: Any, right: Any) -> tuple[ParityFinding, ...]:
    result: list[ParityFinding] = []
    if left.presence != right.presence:
        result.append(
            _finding(
                "PRESENCE_STATE_MISMATCH",
                ParityDimension.CONFIGURATION_FIELDS,
                FindingStatus.MISMATCH,
                left.field_path,
                f"{left.presence.value} differs from {right.presence.value}.",
            )
        )
    if left.value is None or right.value is None:
        return tuple(result)
    if left.value.value_type != right.value.value_type:
        result.append(
            _finding(
                "VALUE_TYPE_MISMATCH",
                ParityDimension.CONFIGURATION_FIELDS,
                FindingStatus.MISMATCH,
                left.field_path,
                f"{left.value.value_type.value} differs from {right.value.value_type.value}.",
            )
        )
    elif left.value != right.value:
        code = (
            "EXPLICIT_NULL_MISMATCH"
            if "EXPLICIT_NULL" in {left.presence.value, right.presence.value}
            else "VALUE_MISMATCH"
        )
        result.append(
            _finding(
                code,
                ParityDimension.CONFIGURATION_FIELDS,
                FindingStatus.MISMATCH,
                left.field_path,
                "Canonical typed values differ.",
            )
        )
    if left.provenance != right.provenance and "default" in (left.provenance + right.provenance):
        result.append(
            _finding(
                "DEFAULT_PROVENANCE_MISMATCH",
                ParityDimension.CONFIGURATION_FIELDS,
                FindingStatus.MISMATCH,
                left.field_path,
                "Explicit default provenance differs.",
            )
        )
    return tuple(result)


def _finding(
    code: str, dimension: ParityDimension, status: FindingStatus, subject: str, detail: str
) -> ParityFinding:
    return ParityFinding(
        code=code, dimension=dimension, status=status, subject=subject, detail=detail
    )


def _token_key(token: Any) -> str:
    return canonical_sha256(token.model_dump(mode="json"))
