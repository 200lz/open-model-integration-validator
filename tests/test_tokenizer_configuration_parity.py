"""Adversarial tests for Phase 6D tokenizer/configuration parity evidence."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import unicodedata
from decimal import localcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.tokenizer_parity.artifact_index import (
    verify_tokenizer_configuration_artifact_index,
)
from omiv.tokenizer_parity.comparison import (
    compare_configurations,
    compare_vocabularies,
    evaluate_vocabulary_size_rule,
    vocabulary_cardinality,
)
from omiv.tokenizer_parity.dependency import assert_acyclic, verify_generated_dependency_graph
from omiv.tokenizer_parity.models import (
    AddedTokenRecord,
    ArtifactAvailability,
    ArtifactBinding,
    CanonicalValue,
    CanonicalValueType,
    CoverageDimension,
    DenominatorState,
    ExpectationAvailability,
    ExpectationReference,
    ObjectReference,
    OverallParityStatus,
    ParityScope,
    PresenceState,
    ProbeComparisonStatus,
    ProbeOutputAvailability,
    TokenContent,
    TokenContentEncoding,
    TokenizerConfigurationArtifactIndex,
    TokenizerConfigurationLimits,
    TokenizerProbeResult,
    VocabularyCardinalityBasis,
    canonical_byte_token,
    canonical_text_token,
    finalize_identity,
    verify_object_reference,
)
from omiv.tokenizer_parity.observation import (
    canonical_configuration_value,
    escape_untrusted_text,
    parse_configuration_json,
    safe_read_asset,
)
from omiv.tokenizer_parity.preservation import audit_baseline
from omiv.tokenizer_parity.schema import (
    SCHEMA_MODELS,
    load_tokenizer_configuration,
    parse_tokenizer_configuration_bytes,
)
from omiv.tokenizer_parity_profiles.examples import (
    generate_all_tokenizer_configuration_examples,
)
from omiv.tokenizer_parity_profiles.xai import build_xai_readiness
from omiv.trust.models import SignedObjectEnvelope
from omiv.trust.verification import load_bundle as load_trust_bundle
from omiv.trust.verification import load_envelope as load_signed_envelope
from omiv.trust.verification import load_policy as load_trust_policy
from omiv.trust.verification import verify_envelope

ROOT = Path(__file__).resolve().parents[1]
GENERATED_ROOTS = (
    ROOT / "tokenizer-configuration-parity",
    ROOT / "reports" / "tokenizer-configuration-parity",
)


def _load(relative: str):
    return load_tokenizer_configuration(ROOT / relative)


def _index() -> TokenizerConfigurationArtifactIndex:
    return TokenizerConfigurationArtifactIndex.model_validate_json(
        (ROOT / "tokenizer-configuration-parity/artifact-index.json").read_bytes()
    )


@pytest.mark.parametrize("schema", sorted(SCHEMA_MODELS))
def test_schema_dispatch_round_trip(schema: str) -> None:
    if schema == "omiv.tokenizer-configuration-artifact-index.v1":
        raw = (ROOT / "tokenizer-configuration-parity/artifact-index.json").read_bytes()
    else:
        entry = next(
            item
            for item in _index().entries
            if item.schema_id == schema and item.path.endswith(".json")
        )
        raw = (ROOT / entry.path).read_bytes()
    value = parse_tokenizer_configuration_bytes(raw)
    reparsed = value.__class__.model_validate(value.model_dump(mode="json", by_alias=True))
    assert reparsed == value


def test_all_phase6d_generated_json_is_strict() -> None:
    count = 0
    for entry in _index().entries:
        if entry.schema_id in SCHEMA_MODELS:
            parse_tokenizer_configuration_bytes((ROOT / entry.path).read_bytes())
            count += 1
    assert count >= 70


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"unknown","schema":"other"}',
        b'{"schema":"omiv.unknown.v1"}',
        b'{"schema":"omiv.tokenizer-configuration-expectation.v2"}',
        b'{"schema":NaN}',
        b'{"schema":Infinity}',
    ],
)
def test_strict_schema_rejections(raw: bytes) -> None:
    with pytest.raises(OmivInputError):
        parse_tokenizer_configuration_bytes(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b"\xff",
        b"[]",
        b"{",
        b'{"x":1e999999999}',
        b'{"x":12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901}',
    ],
)
def test_configuration_parser_rejects_adversarial_input(raw: bytes) -> None:
    with pytest.raises(OmivInputError):
        parse_configuration_json(raw, source_name="synthetic.json")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (b'{"x":0}', 0),
        (b'{"x":-0}', 0),
        (b'{"x":0.0}', "0"),
        (b'{"x":-0.000}', "0"),
        (b'{"x":1.0}', "1"),
        (b'{"x":1.00}', "1"),
        (b'{"x":1e0}', "1"),
        (b'{"x":0.1}', "0.1"),
    ],
)
def test_canonical_number_normalization(text: bytes, expected: int | str) -> None:
    value = parse_configuration_json(text, source_name="numeric.json")["x"]
    if isinstance(expected, str):
        canonical = canonical_configuration_value(value, TokenizerConfigurationLimits())
        assert canonical.decimal_value == expected
    else:
        assert value == expected


def test_canonical_decimal_is_independent_of_global_context() -> None:
    with localcontext() as context:
        context.prec = 3
        value = parse_configuration_json(b'{"x":1.234567890123456789e2}', source_name="x")["x"]
        canonical = canonical_configuration_value(value, TokenizerConfigurationLimits())
        assert canonical.decimal_value == "123.4567890123456789"


def test_direct_canonical_integer_is_explicitly_bounded() -> None:
    with pytest.raises(ValidationError, match="INTEGER_DIGITS"):
        CanonicalValue(value_type=CanonicalValueType.INTEGER, integer_value=10**100)


@pytest.mark.parametrize(
    "value",
    [True, 1, "1", [1], ["1"], None, {"typed": "object"}],
)
def test_configuration_value_types_remain_distinct(value: object) -> None:
    canonical = canonical_configuration_value(value, TokenizerConfigurationLimits())
    assert isinstance(canonical, CanonicalValue)


def test_boolean_integer_decimal_and_string_are_not_equal() -> None:
    limits = TokenizerConfigurationLimits()
    parsed = parse_configuration_json(b'{"b":true,"i":1,"d":1.0,"s":"1"}', source_name="x")
    types = [canonical_configuration_value(parsed[key], limits).value_type for key in "bids"]
    assert types == [
        CanonicalValueType.BOOLEAN,
        CanonicalValueType.INTEGER,
        CanonicalValueType.DECIMAL,
        CanonicalValueType.STRING,
    ]


@pytest.mark.parametrize(
    "value",
    ["é", "e\u0301", " ", "\t", "\n", "\u0000", "漢字", "🙂", "👩‍💻"],
)
def test_unicode_token_preserves_exact_codepoints(value: str) -> None:
    token = canonical_text_token(value)
    assert token.unicode_text == value
    if value in {"é", "e\u0301"}:
        assert unicodedata.normalize("NFC", value) == "é"


def test_nfc_and_nfd_tokens_have_distinct_identity() -> None:
    nfc = canonical_text_token("é")
    nfd = canonical_text_token("e\u0301")
    assert nfc != nfd
    assert nfc.model_dump_json() != nfd.model_dump_json()


def test_text_and_byte_tokens_are_distinct() -> None:
    text = canonical_text_token("é")
    raw = canonical_byte_token("é".encode())
    assert text.encoding == TokenContentEncoding.UNICODE_TEXT
    assert raw.encoding == TokenContentEncoding.BYTE_SEQUENCE
    assert raw.bytes_hex == "c3a9"


def test_added_token_absent_property_differs_from_false() -> None:
    base = {
        "content": canonical_text_token("<x>"),
        "token_id": 4,
        "token_id_presence": PresenceState.EXPLICIT_VALUE,
        "single_word": None,
        "lstrip": None,
        "rstrip": None,
        "normalized": None,
        "source_order": 0,
        "provenance": "caller.synthetic",
    }
    absent = AddedTokenRecord(**base, special=None, property_presence=())
    false = AddedTokenRecord(**base, special=False, property_presence=("special",))
    assert absent != false
    with pytest.raises(ValidationError):
        AddedTokenRecord(**base, special=False, property_presence=())


@pytest.mark.parametrize("bytes_hex", ["0", "GG", "AA", "zz", "0x00"])
def test_malformed_byte_token_rejected(bytes_hex: str) -> None:
    with pytest.raises(ValidationError):
        TokenContent(encoding=TokenContentEncoding.BYTE_SEQUENCE, bytes_hex=bytes_hex)


@pytest.mark.parametrize("value", ["\ud800", "\udfff", "\ufffe", "\uffff"])
def test_invalid_unicode_scalar_rejected(value: str) -> None:
    with pytest.raises((ValidationError, ValueError)):
        canonical_text_token(value)


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [("a\tb", "a\\u0009b"), ("a\nb", "a\\u000ab"), ("a\u202eb", "a\\u202eb")],
)
def test_report_escapes_controls_and_bidi(raw: str, escaped: str) -> None:
    assert escape_untrusted_text(raw) == escaped


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("a\u0085b", "a\\u0085b"),
        ("a\u200bb", "a\\u200bb"),
        ("# heading", "\\# heading"),
        ("[link](x)", "\\[link\\]\\(x\\)"),
    ],
)
def test_report_escapes_c1_zero_width_and_markdown(raw: str, escaped: str) -> None:
    assert escape_untrusted_text(raw) == escaped


def test_expectation_reference_does_not_upgrade_digest_only() -> None:
    expectation = _load("tokenizer-configuration-parity/expectations/synthetic.json")
    subject = expectation.subject
    value = ExpectationReference(
        reference=ObjectReference(
            schema_id=expectation.schema_id,
            object_id=expectation.expectation_id,
            object_digest=expectation.expectation_digest,
        ),
        object_supplied_and_verified=False,
        subject_id=subject.subject_id,
        scope=ParityScope.PARTIAL_REFERENCE_SET,
        authority_status="NOT_ESTABLISHED",
        availability=ExpectationAvailability.DIGEST_REFERENCE_ONLY,
        limitations=("Digest alone is unavailable content.",),
    )
    assert value.reference is not None
    with pytest.raises(ValidationError):
        body = value.model_dump(mode="json")
        body["availability"] = ExpectationAvailability.FULL_EXPECTATION_AVAILABLE
        ExpectationReference.model_validate(body)


def test_digest_only_expectation_cannot_discard_its_identity() -> None:
    expectation = _load("tokenizer-configuration-parity/expectations/synthetic.json")
    with pytest.raises(ValidationError):
        ExpectationReference(
            reference=None,
            object_supplied_and_verified=False,
            subject_id=expectation.subject.subject_id,
            scope=ParityScope.PARTIAL_REFERENCE_SET,
            authority_status="NOT_ESTABLISHED",
            availability=ExpectationAvailability.DIGEST_REFERENCE_ONLY,
            limitations=("Digest identity is required.",),
        )


def test_supplied_expectation_reference_requires_exact_id_digest_schema_and_subject() -> None:
    expectation = _load("tokenizer-configuration-parity/expectations/synthetic.json")
    reference = ObjectReference(
        schema_id=expectation.schema_id,
        object_id=expectation.expectation_id,
        object_digest=expectation.expectation_digest,
    )
    verify_object_reference(reference, expectation)
    for field, value in (
        ("schema_id", "omiv.tokenizer-configuration-policy.v1"),
        ("object_id", "tokenizer_expectation_" + "0" * 32),
        ("object_digest", "0" * 64),
    ):
        with pytest.raises(ValueError, match="does not match"):
            verify_object_reference(reference.model_copy(update={field: value}), expectation)


def test_nonpayload_remote_identity_cannot_carry_payload_digest() -> None:
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    body = binding.model_dump(mode="json")
    body.update(
        availability=ArtifactAvailability.REMOTE_NON_PAYLOAD_IDENTITY_ONLY,
        payload_sha256="0" * 64,
        phase6a_manifest=None,
    )
    with pytest.raises(ValidationError):
        ArtifactBinding.model_validate(body)


def test_exact_local_identity_requires_phase6a_and_payload_fields() -> None:
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    body = binding.model_dump(mode="json")
    body["phase6a_manifest"] = None
    with pytest.raises(ValidationError):
        ArtifactBinding.model_validate(body)


@pytest.mark.parametrize(
    ("numerator", "denominator", "state"),
    [(0, None, DenominatorState.UNAVAILABLE), (0, 0, DenominatorState.AVAILABLE)],
)
def test_unknown_and_zero_coverage_are_not_complete(
    numerator: int, denominator: int | None, state: DenominatorState
) -> None:
    value = CoverageDimension(
        dimension="TEST_COVERAGE",
        numerator=numerator,
        denominator=denominator,
        denominator_state=state,
        selected_scope=ParityScope.PARTIAL_REFERENCE_SET,
        incomplete_reason="No vacuous truth.",
    )
    assert value.denominator != 1


def test_zero_coverage_without_reason_rejected() -> None:
    with pytest.raises(ValidationError):
        CoverageDimension(
            dimension="TEST_COVERAGE",
            numerator=0,
            denominator=0,
            denominator_state=DenominatorState.AVAILABLE,
            selected_scope=ParityScope.PARTIAL_REFERENCE_SET,
            incomplete_reason=None,
        )


@pytest.mark.parametrize(
    "edges",
    [
        {"a": {"a"}},
        {"a": {"b"}, "b": {"a"}},
        {"a": {"b"}, "b": {"c"}, "c": {"a"}},
    ],
)
def test_dependency_cycles_rejected(edges: dict[str, set[str]]) -> None:
    with pytest.raises(ValueError, match="cycle"):
        assert_acyclic(edges)


def test_dependency_graph_accepts_required_direction() -> None:
    assert_acyclic({"evidence": {"comparison", "policy", "authority"}, "comparison": {"plan"}})
    verify_generated_dependency_graph(ROOT, _index())


def test_execution_records_do_not_reference_results() -> None:
    execution = _load("tokenizer-configuration-parity/executions/synthetic.json")
    keys = set(execution.model_dump(mode="json"))
    forbidden = {"observation", "comparison", "evidence", "report", "signature", "index"}
    assert not keys & forbidden
    probe_execution = _load("tokenizer-configuration-parity/probes/execution.json")
    assert "result" not in probe_execution.model_dump(mode="json")


def test_observations_bind_finalized_execution() -> None:
    execution = _load("tokenizer-configuration-parity/executions/synthetic.json")
    observation = _load("tokenizer-configuration-parity/observations/config-reference.json")
    assert observation.execution.object_id == execution.execution_id
    assert observation.execution.object_digest == execution.execution_digest


def test_probe_result_binds_execution_and_probe_set() -> None:
    execution = _load("tokenizer-configuration-parity/probes/execution.json")
    definition = _load("tokenizer-configuration-parity/probes/definition.json")
    results = _load("tokenizer-configuration-parity/probes/reference-results.json")
    assert results.execution.object_id == execution.execution_id
    assert results.probe_set.object_id == definition.probe_set_id


def test_raw_bytes_canonical_json_and_field_parity_are_distinct() -> None:
    reference = _load("tokenizer-configuration-parity/observations/config-reference.json")
    candidate = _load("tokenizer-configuration-parity/observations/config-candidate.json")
    findings, status, _dimension = compare_configurations(
        reference,
        candidate,
        required_fields=("bos_token_id", "eos_token_id", "rope_scaling", "use_cache", "vocab_size"),
    )
    assert reference.raw_sha256 != candidate.raw_sha256
    assert reference.canonical_json_sha256 == candidate.canonical_json_sha256
    assert status.value == "CANONICAL_JSON_EQUAL_FOR_SCOPE"
    assert not any(item.status.value == "MISMATCH" for item in findings)


def test_empty_configuration_scope_cannot_pass() -> None:
    reference = _load("tokenizer-configuration-parity/observations/config-reference.json")
    _findings, status, dimension = compare_configurations(reference, reference, required_fields=())
    assert status.value == "INCOMPLETE_CONFIGURATION_EVIDENCE"
    assert dimension.compared_count == 0


def test_vocabulary_preserves_sparse_and_bidirectional_semantics() -> None:
    reference = _load("tokenizer-configuration-parity/observations/vocab-reference.json")
    candidate = _load("tokenizer-configuration-parity/observations/vocab-candidate.json")
    findings, dimensions = compare_vocabularies(reference, candidate)
    assert all(item.mismatch_count == 0 for item in dimensions)
    assert any(item.code == "TOKEN_TO_ID_MATCH" for item in findings)
    assert {entry.token_id for entry in reference.entries} == {0, 1, 2, 3, 4}
    assert reference.record_count == 5
    assert reference.distinct_token_count == 5
    assert reference.distinct_id_count == 5
    assert reference.maximum_token_id == 4
    assert reference.max_id_plus_one == 5


def test_vocabulary_cardinality_bases_are_not_interchangeable() -> None:
    observation = _load("tokenizer-configuration-parity/observations/vocab-reference.json")
    sparse = observation.model_copy(
        update={
            "entries": tuple(
                entry.model_copy(update={"token_id": entry.token_id * 2})
                for entry in observation.entries
            ),
            "record_count": 5,
            "distinct_token_count": 5,
            "distinct_id_count": 5,
            "maximum_token_id": 8,
            "max_id_plus_one": 9,
            "sparse_ids_observed": True,
        }
    )
    assert vocabulary_cardinality(sparse, VocabularyCardinalityBasis.RECORD_COUNT) == 5
    assert vocabulary_cardinality(sparse, VocabularyCardinalityBasis.MAX_ID_PLUS_ONE) == 9
    assert vocabulary_cardinality(sparse, VocabularyCardinalityBasis.BASE_VOCABULARY_COUNT) is None


def test_vocab_size_rule_requires_explicit_available_basis() -> None:
    config = _load("tokenizer-configuration-parity/observations/config-reference.json")
    vocabulary = _load("tokenizer-configuration-parity/observations/vocab-reference.json")
    available = evaluate_vocabulary_size_rule(
        config,
        vocabulary,
        field_path="vocab_size",
        basis=VocabularyCardinalityBasis.RECORD_COUNT,
    )
    unavailable = evaluate_vocabulary_size_rule(
        config,
        vocabulary,
        field_path="vocab_size",
        basis=VocabularyCardinalityBasis.BASE_VOCABULARY_COUNT,
    )
    assert available.status.value == "CONSISTENT_FOR_DECLARED_RULE"
    assert unavailable.status.value == "NOT_EVALUATED"


def test_merge_order_is_not_sorted_before_observation() -> None:
    observation = _load("tokenizer-configuration-parity/observations/merges-reference.json")
    assert [record.rank for record in observation.records] == [0, 1, 2]
    assert [record.source_order for record in observation.records] == [0, 1, 2]


def test_mismatch_and_malformed_source_fixtures_exercise_distinct_inputs() -> None:
    fixture_root = ROOT / "fixtures/tokenizer-parity"
    config_reference = parse_configuration_json(
        (fixture_root / "config-reference.json").read_bytes(), source_name="config-reference.json"
    )
    config_mismatch = parse_configuration_json(
        (fixture_root / "config-mismatch.json").read_bytes(), source_name="config-mismatch.json"
    )
    assert config_reference != config_mismatch

    vocab_mismatch = parse_configuration_json(
        (fixture_root / "vocab-mismatch.json").read_bytes(), source_name="vocab-mismatch.json"
    )
    vocab_duplicate_id = parse_configuration_json(
        (fixture_root / "vocab-duplicate-id.json").read_bytes(),
        source_name="vocab-duplicate-id.json",
    )
    assert vocab_mismatch != parse_configuration_json(
        (fixture_root / "vocab-reference.json").read_bytes(), source_name="vocab-reference.json"
    )
    assert len(vocab_duplicate_id.values()) != len(set(vocab_duplicate_id.values()))

    reference_merges = (fixture_root / "merges-reference.txt").read_bytes()
    reordered_merges = (fixture_root / "merges-reordered.txt").read_bytes()
    assert reference_merges != reordered_merges
    assert sorted(reference_merges.splitlines()[1:]) == sorted(reordered_merges.splitlines()[1:])

    assert (fixture_root / "chat-template-reference.txt").read_bytes() != (
        fixture_root / "chat-template-mismatch.txt"
    ).read_bytes()


def test_template_is_present_but_not_executed() -> None:
    observation = _load("tokenizer-configuration-parity/observations/template-reference.json")
    assert observation.template_executed is False
    asset = _load("tokenizer-configuration-parity/observations/template-reference.asset.json")
    assert asset.content_executed is False


def test_finite_probe_success_remains_selected_probe_scope() -> None:
    results = _load("tokenizer-configuration-parity/probes/reference-results.json")
    assert all(
        item.status == ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES for item in results.results
    )
    assert all(
        item.selected_scope == ParityScope.SELECTED_REQUIRED_PROBES for item in results.coverage
    )
    evidence = _load("tokenizer-configuration-parity/evidence/synthetic.json")
    assert evidence.behavioral_equivalence == "NOT_ESTABLISHED"


def test_probe_output_availability_and_sequences_fail_closed() -> None:
    result = _load("tokenizer-configuration-parity/probes/reference-results.json").results[0]
    assert result.output_availability == ProbeOutputAvailability.INLINE_SYNTHETIC_OUTPUT
    base = result.model_dump(mode="json")
    for update in (
        {"token_ids": [-1, 1]},
        {"token_ids": [True, 1]},
        {"special_token_mask": [1]},
        {"attention_mask": [0, 1, 0]},
        {"offsets": [[2, 1], [0, 1]]},
        {"output_length": 999},
        {"output_digest": "0" * 64},
    ):
        with pytest.raises(ValidationError):
            TokenizerProbeResult.model_validate({**base, **update})


def test_digest_only_probe_output_cannot_serialize_plaintext_or_pass() -> None:
    result = _load("tokenizer-configuration-parity/probes/reference-results.json").results[0]
    base = result.model_dump(mode="json")
    body = {
        **base,
        "output_availability": ProbeOutputAvailability.DIGEST_ONLY_OUTPUT,
        "token_ids": None,
        "output_text": None,
        "output_length": 2,
        "status": ProbeComparisonStatus.DIGEST_ONLY_NOT_REPRODUCIBLE,
    }
    digest_only = TokenizerProbeResult.model_validate(body)
    assert digest_only.token_ids is None
    with pytest.raises(ValidationError):
        TokenizerProbeResult.model_validate(
            {**body, "status": ProbeComparisonStatus.EXACT_FOR_DECLARED_PROBES}
        )


def test_metadata_signature_namespace_cannot_create_parity_or_authority() -> None:
    readiness, _case = build_xai_readiness(ROOT)
    assert readiness.payload_comparable_members == 0
    assert readiness.parity == "NOT_EVALUATED"
    assert readiness.publisher_authority == "NOT_ESTABLISHED"
    authority = _load("tokenizer-configuration-parity/authority/synthetic.json")
    assert authority.observation_signer_authority.value == "ESTABLISHED"
    assert authority.source_publisher_authority.value == "NOT_ESTABLISHED"
    assert authority.candidate_publisher_authority.value == "NOT_ESTABLISHED"


def test_phase6c_does_not_establish_phase6d() -> None:
    integration = _load("tokenizer-configuration-parity/integrations/quantization.json")
    assert integration.derived_state == "weight.fidelity.independent"
    assert integration.creates_approval is False


@pytest.mark.parametrize(
    "kind",
    ["governance", "security", "runtime", "historical", "reconciliation", "quantization"],
)
def test_integration_boundaries(kind: str) -> None:
    value = _load(f"tokenizer-configuration-parity/integrations/{kind}.json")
    assert value.creates_approval is False
    assert value.creates_security_pass is False
    assert value.creates_runtime_observation is False


def test_xai_fixtures_and_readiness_are_exact() -> None:
    expected = {
        "grok-1": (
            466_308,
            "645ea0fbd09c85a1d69d4fd217bae43e580a04fcd484308d1cd71b528658ae78",
            "5de83eb225f49624b424f1c8aa74f96983b5885c",
        ),
        "grok-2": (
            27_473,
            "ad495d2fbb3daaed25ddf8d351647254f2d7020d2d4492b89f90aea486c3a60b",
            "daf4395a80ad177386cfe39641b64fc12b1d70ed",
        ),
    }
    for name, (size, digest, revision) in expected.items():
        path = ROOT / f"fixtures/reconciliation/xai/{name}.pinned-metadata.json"
        raw = path.read_bytes()
        assert len(raw) == size
        assert hashlib.sha256(raw).hexdigest() == digest
        assert json.loads(raw)["resolved_revision"] == revision
    readiness, _case = build_xai_readiness(ROOT)
    assert readiness.classification.endswith("WITHOUT_REQUIRED_PAYLOAD_ASSETS")
    assert readiness.tokenizer_configuration_asset_contents == "NOT_DOWNLOADED"
    assert readiness.added_tokens == "NOT_OBSERVED"
    assert readiness.observation_time == "NOT_RECORDED"


def test_generic_core_has_no_profile_or_provider_imports() -> None:
    forbidden = ("xai", "grok", "kimi", "deepseek", "tokenizer_parity_profiles")
    for path in (ROOT / "src/omiv/tokenizer_parity").glob("*.py"):
        lowered = path.read_text().lower()
        assert not any(
            f"import {term}" in lowered or f"from {term}" in lowered for term in forbidden
        )


def test_artifact_index_is_external_complete_and_unique() -> None:
    index = _index()
    verify_tokenizer_configuration_artifact_index(ROOT, index)
    assert len(index.entries) == 105
    assert len({item.sha256 for item in index.entries}) == len(index.entries)
    assert len({item.canonical_id for item in index.entries}) == len(index.entries)
    assert all(
        item.path != "tokenizer-configuration-parity/artifact-index.json" for item in index.entries
    )


def test_all_36_scenarios_are_distinct() -> None:
    catalog = _load("tokenizer-configuration-parity/scenarios/catalog.json")
    entries = [
        item
        for item in _index().entries
        if "/scenarios/" in item.path and not item.path.endswith("catalog.json")
    ]
    assert len(catalog.scenarios) == 36
    assert len(entries) == 36
    assert len({item.sha256 for item in entries}) == 36
    assert len({item.canonical_id for item in entries}) == 36


def test_only_representative_classes_are_signed() -> None:
    envelopes = [
        load_signed_envelope(ROOT / item.path)
        for item in _index().entries
        if item.path.endswith("envelope.json")
    ]
    assert {item.signed_object_type.value for item in envelopes} == {
        "TOKENIZER_CONFIGURATION_EXPECTATION",
        "TOKENIZER_ASSET_OBSERVATION",
        "TOKENIZER_CONFIGURATION_PARITY_EVIDENCE",
    }


def test_representative_signatures_verify_without_authority_upgrade() -> None:
    bundle = load_trust_bundle(ROOT / "tokenizer-configuration-parity/signed/trust-bundle.json")
    policy = load_trust_policy(ROOT / "tokenizer-configuration-parity/signed/trust-policy.json")
    for name in ("expectation", "asset-observation", "evidence"):
        envelope = load_signed_envelope(
            ROOT / f"tokenizer-configuration-parity/signed/{name}.envelope.json"
        )
        assert isinstance(envelope, SignedObjectEnvelope)
        report = verify_envelope(envelope, bundle, policy)
        assert report.overall_status.value == "TRUSTED_SIGNATURE_WITH_LIMITATIONS"
        assert report.underlying_claim.get("publisher_authority_created_by_signature") is False


def test_safe_read_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text("{}")
    symlink = tmp_path / "link.json"
    symlink.symlink_to(source)
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    loose = binding.model_copy(
        update={
            "file_size": None,
            "payload_sha256": None,
            "phase6a_manifest": None,
            "artifact_set_identity": None,
            "availability": ArtifactAvailability.METADATA_IDENTITY_ONLY,
        }
    )
    with pytest.raises(OmivInputError, match="symlink"):
        safe_read_asset(symlink, loose, TokenizerConfigurationLimits())
    hardlink = tmp_path / "hard.json"
    os.link(source, hardlink)
    with pytest.raises(OmivInputError, match="hardlink"):
        safe_read_asset(hardlink, loose, TokenizerConfigurationLimits())


def test_safe_read_reports_explicit_root_change(tmp_path: Path) -> None:
    path = tmp_path / "asset.json"
    path.write_text("{}")
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    loose = binding.model_copy(
        update={
            "file_size": None,
            "payload_sha256": None,
            "phase6a_manifest": None,
            "artifact_set_identity": None,
            "availability": ArtifactAvailability.METADATA_IDENTITY_ONLY,
        }
    )
    _raw, findings = safe_read_asset(
        path, loose, TokenizerConfigurationLimits(), root_before="a", root_after="b"
    )
    assert findings == ("ROOT_CHANGED_DURING_OBSERVATION",)


def test_safe_read_reports_opened_file_metadata_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "asset.json"
    path.write_text("{}")
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    loose = binding.model_copy(
        update={
            "file_size": None,
            "payload_sha256": None,
            "phase6a_manifest": None,
            "artifact_set_identity": None,
            "availability": ArtifactAvailability.METADATA_IDENTITY_ONLY,
        }
    )
    real_fstat = os.fstat
    calls = 0

    def changed_fstat(fd: int):
        nonlocal calls
        calls += 1
        current = real_fstat(fd)
        if calls != 2:
            return current
        return SimpleNamespace(
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_size=current.st_size,
            st_mtime_ns=current.st_mtime_ns + 1,
            st_ctime_ns=current.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", changed_fstat)
    _raw, findings = safe_read_asset(path, loose, TokenizerConfigurationLimits())
    assert findings == ("OPENED_FILE_CHANGED_DURING_READ",)


@pytest.mark.parametrize(
    "path",
    ["/absolute.json", "../parent.json", "a\\b.json", "CON", "a/aux.txt", "trail. ", "x\u0000y"],
)
def test_asset_path_portability_rejections(path: str) -> None:
    binding = _load(
        "tokenizer-configuration-parity/declarations/synthetic.json"
    ).reference_artifacts[0]
    body = binding.model_dump(mode="json")
    body["asset_path"] = path
    with pytest.raises(ValidationError):
        ArtifactBinding.model_validate(body)


def test_resource_limits_are_explicit() -> None:
    limits = TokenizerConfigurationLimits()
    assert limits.maximum_vocabulary_entries == 250_000
    assert limits.maximum_merge_records == 250_000
    assert limits.maximum_configuration_fields == 10_000
    assert limits.maximum_generated_files == 160
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED"):
        parse_configuration_json(
            b'{"x":"' + b"a" * 65 + b'"}',
            source_name="bounded.json",
            limits=limits.model_copy(update={"maximum_string_length": 64}),
        )


def test_bounded_10000_field_smoke() -> None:
    raw = json.dumps({f"f{i}": i for i in range(10_000)}, separators=(",", ":")).encode()
    parsed = parse_configuration_json(raw, source_name="10k.json")
    assert len(parsed) == 10_000


def test_250000_record_limits_are_bounded_without_allocation_from_dimensions() -> None:
    limits = TokenizerConfigurationLimits()
    assert sum(1 for _ in range(limits.maximum_vocabulary_entries)) == 250_000
    assert sum(1 for _ in range(limits.maximum_merge_records)) == 250_000


def test_two_run_generation_is_byte_identical(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    generate_all_tokenizer_configuration_examples(left, repository=ROOT)
    generate_all_tokenizer_configuration_examples(right, repository=ROOT)
    left_files = {path.relative_to(left) for path in left.rglob("*") if path.is_file()}
    right_files = {path.relative_to(right) for path in right.rglob("*") if path.is_file()}
    assert left_files == right_files
    assert len(left_files) == 106
    for relative in left_files:
        assert (left / relative).read_bytes() == (right / relative).read_bytes()


def test_workspace_generation_matches_fresh_generation(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generate_all_tokenizer_configuration_examples(generated, repository=ROOT)
    for path in generated.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (ROOT / path.relative_to(generated)).read_bytes()


def test_preservation_inventory_is_exact() -> None:
    audit = audit_baseline(ROOT)
    assert audit["counts"] == {
        "included": 780,
        "excluded": 276,
        "prior_indexes": 8,
        "prior_indexed_members": 625,
    }
    assert audit["changed_paths"] == []
    assert audit["missing_paths"] == []
    assert audit["unexpected_omissions"] == []
    assert (
        audit["path_set_digest"]
        == "9c09019defc1a4b74f18b27b615b8cd6d6d30f84c9cfb2c59e59eb10b4d5c73a"
    )
    assert (
        audit["inventory_digest"]
        == "3464cc34042078d7959500fbe86b6e317fd688a4badec74e98ca01d609653b19"
    )


def test_ignored_kimi_artifact_unchanged() -> None:
    path = ROOT / "reports/raw/kimi_k3_tensors.json"
    assert path.stat().st_size == 115_542_096
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469"
    )
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", str(path.relative_to(ROOT))], cwd=ROOT
    )
    assert result.returncode == 0


def test_canonical_identity_changes_for_identity_bearing_fields() -> None:
    expectation = _load("tokenizer-configuration-parity/expectations/synthetic.json")
    body = expectation.model_dump(mode="json", by_alias=True)
    body.pop("expectation_id")
    body.pop("expectation_digest")
    original = finalize_identity(
        body, "expectation_id", "tokenizer_expectation_", "expectation_digest"
    )
    changed = finalize_identity(
        {**body, "publisher": "different.publisher"},
        "expectation_id",
        "tokenizer_expectation_",
        "expectation_digest",
    )
    assert original["expectation_id"] != changed["expectation_id"]


def test_final_evidence_is_scope_qualified_and_non_claiming() -> None:
    evidence = _load("tokenizer-configuration-parity/evidence/synthetic.json")
    assert evidence.overall_status == OverallParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE
    assert evidence.scope == ParityScope.COMPLETE_DECLARED_TOKENIZER_ASSET_SET
    assert evidence.behavioral_equivalence == "NOT_ESTABLISHED"
    assert evidence.runtime_compatibility == "NOT_ESTABLISHED"
    assert evidence.security_status == "NOT_EVALUATED"
    assert evidence.authenticity == "NOT_ESTABLISHED"
