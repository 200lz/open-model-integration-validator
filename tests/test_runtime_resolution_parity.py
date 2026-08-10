"""Focused semantic and determinism tests for Phase 6E."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.external_artifacts import (
    KIMI_K3_TENSOR_INVENTORY,
    ExternalArtifactStatus,
    observe_external_artifact,
)
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubjectClass
from omiv.runtime_resolution.artifact_index import verify_runtime_resolution_artifact_index
from omiv.runtime_resolution.building import (
    build_identifier_classification,
    build_policy,
    build_requested_identifier,
    build_resolution_execution,
    build_resolution_plan,
    build_resolution_receipt,
    build_runtime_binding,
)
from omiv.runtime_resolution.comparison import selected_logit_max_absolute_error
from omiv.runtime_resolution.dependency import (
    assert_acyclic,
    verify_generated_dependency_graph,
)
from omiv.runtime_resolution.models import (
    IDENTITY_SPECS,
    AuthorityDimension,
    BackendResult,
    ContentAvailability,
    ContinuityOutcome,
    DeploymentDeclaration,
    HistoricalCutoffOutcome,
    IdentifierKind,
    LogitSample,
    ModelRuntimeBinding,
    ObservationLevel,
    OutputProvenanceEvidence,
    ProofAvailability,
    ProofReference,
    ProvenanceVerificationStatus,
    RegistryResolutionReceipt,
    ResolutionMechanism,
    ResolutionStatus,
    RuntimeArtifactExpectation,
    RuntimeBindingOutcome,
    RuntimeIdentityExpectation,
    RuntimeResolutionArtifactIndex,
    RuntimeResolutionLimits,
    ToolCallRecord,
    TypedParameter,
    content_identity,
    finalize_identity,
)
from omiv.runtime_resolution.preservation import audit_baseline
from omiv.runtime_resolution.reporting import safe_text
from omiv.runtime_resolution.resolution import assess_resolution_continuity, known_as_of_cutoff
from omiv.runtime_resolution.schema import (
    SCHEMA_MODELS,
    load_runtime_resolution,
    parse_runtime_resolution_bytes,
)
from omiv.runtime_resolution_profiles.anthropic import build_anthropic_practice
from omiv.runtime_resolution_profiles.examples import (
    SCENARIOS,
    generate_all_runtime_resolution_examples,
)
from omiv.runtime_resolution_profiles.public_documents import (
    EXPECTED,
    load_public_document_fixture,
)
from omiv.runtime_resolution_profiles.xai import build_xai_practice
from omiv.trust.models import SignedObjectEnvelope, TrustBundle, TrustPolicy
from omiv.trust.verification import verify_envelope

BASELINE = "77763002ef93ba3274145aa02ded476e488158ee"


@pytest.fixture(scope="module")
def subject():
    return build_product_subject(
        ProductSubjectClass.DEPLOYMENT_PACKAGE,
        "runtime-resolution.phase6e-test",
        synthetic_scope(project="project.runtime-resolution", environment="environment.test"),
    )


@pytest.fixture(scope="module")
def requested(subject):
    return build_requested_identifier(
        subject, "synthetic-latest", kind=IdentifierKind.MUTABLE_ALIAS
    )


@pytest.fixture(scope="module")
def execution(subject, requested):
    classification = build_identifier_classification(
        subject, requested, kind=IdentifierKind.MUTABLE_ALIAS
    )
    return build_resolution_execution(
        subject, build_resolution_plan(subject, requested, classification)
    )


def _receipt(subject, requested, execution, resolved: str, at: str):
    return build_resolution_receipt(
        subject,
        execution,
        requested,
        status=ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
        resolved=resolved,
        resolved_kind=IdentifierKind.VERSIONED_IDENTIFIER,
        level=ObservationLevel.CALLER_DECLARED,
        evidence_digest=execution.execution_digest,
        resolved_at=at,
    )


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase6e-generated")
    generate_all_runtime_resolution_examples(root, repository=Path.cwd())
    return root


def test_schema_inventory_covers_required_top_level_types() -> None:
    assert len(IDENTITY_SPECS) == 32
    assert set(SCHEMA_MODELS) == set(IDENTITY_SPECS)


def test_generated_canonical_round_trips(generated: Path) -> None:
    for path in sorted((generated / "runtime-resolution-parity").rglob("*.json")):
        raw = json.loads(path.read_bytes())
        if raw["schema"] in SCHEMA_MODELS:
            parsed = parse_runtime_resolution_bytes(path.read_bytes(), source_name=path.name)
            assert parsed.model_dump(mode="json", by_alias=True) == raw


def test_schema_dispatch_rejects_unknown_schema() -> None:
    with pytest.raises(OmivInputError, match="unsupported"):
        parse_runtime_resolution_bytes(b'{"schema":"omiv.future.v99"}')


def test_duplicate_key_rejected() -> None:
    with pytest.raises(OmivInputError, match="duplicate"):
        parse_runtime_resolution_bytes(b'{"schema":"omiv.future.v99","schema":"x"}')


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b'{"schema":NaN}',
        b'{"schema":Infinity}',
        b'{"schema":-Infinity}',
    ],
)
def test_strict_json_rejects_invalid_utf8_and_nonfinite(raw: bytes) -> None:
    with pytest.raises(OmivInputError):
        parse_runtime_resolution_bytes(raw)


def test_bounded_nesting_rejected() -> None:
    raw = b'{"schema":"omiv.future.v1","x":' + b"[" * 70 + b"0" + b"]" * 70 + b"}"
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED"):
        parse_runtime_resolution_bytes(raw)


def test_canonical_identity_changes_with_subject_and_scope(requested) -> None:
    body = requested.model_dump(mode="json", by_alias=True)
    original = body["identifier_id"]
    body.pop("identifier_id")
    body.pop("identifier_digest")
    body["scope"] = "runtime.changed"
    changed = finalize_identity(body, "identifier_id", "requested_model_", "identifier_digest")
    assert changed["identifier_id"] != original


def test_schema_domain_separation() -> None:
    body = {"schema": "omiv.a.v1", "scope": "same"}
    left = finalize_identity(body, "object_id", "type_a_", "object_digest")
    right = finalize_identity(
        {**body, "schema": "omiv.b.v1"}, "object_id", "type_b_", "object_digest"
    )
    assert left["object_id"] != right["object_id"]


def test_plan_and_execution_are_forward_reference_free(generated: Path) -> None:
    plan = json.loads((generated / "runtime-resolution-parity/resolution-plan.json").read_bytes())
    execution = json.loads(
        (generated / "runtime-resolution-parity/resolution-execution.json").read_bytes()
    )
    forbidden = {"receipt_id", "observation_id", "result_id", "comparison_id", "evidence_id"}
    assert forbidden.isdisjoint(plan)
    assert forbidden.isdisjoint(execution)


def test_backend_execution_is_result_independent(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime-resolution-parity/backends/execution-a.json").read_bytes()
    )
    assert not {"result_id", "observation_id", "comparison_id", "evidence_id"}.intersection(value)


def test_generated_dependency_graph_is_acyclic(generated: Path) -> None:
    index = load_runtime_resolution(
        generated / "runtime-resolution-parity/artifact-index.json",
        RuntimeResolutionArtifactIndex,
    )
    assert isinstance(index, RuntimeResolutionArtifactIndex)
    verify_generated_dependency_graph(generated, index)


def test_dependency_graph_recomputes_target_identity_and_digest(
    generated: Path, tmp_path: Path
) -> None:
    copied = tmp_path / "tampered"
    shutil.copytree(generated, copied)
    target = copied / "runtime-resolution-parity/receipts/t0.json"
    value = json.loads(target.read_bytes())
    value["resolved_identifier"] = "tampered-without-recomputing-identity"
    target.write_text(json.dumps(value), encoding="utf-8")
    index = load_runtime_resolution(
        copied / "runtime-resolution-parity/artifact-index.json",
        RuntimeResolutionArtifactIndex,
    )
    assert isinstance(index, RuntimeResolutionArtifactIndex)
    with pytest.raises(ValueError, match="not recomputable"):
        verify_generated_dependency_graph(copied, index)


def test_dependency_cycle_rejected() -> None:
    with pytest.raises(ValueError, match="cycle"):
        assert_acyclic({"a": {"b"}, "b": {"a"}})


def test_dependency_bounds_rejected() -> None:
    limits = RuntimeResolutionLimits(maximum_dependency_depth=4)
    with pytest.raises(ValueError, match="DEPTH"):
        assert_acyclic({str(i): {str(i + 1)} for i in range(8)}, limits)


def test_requested_equality_is_not_resolved_equality(subject, requested, execution) -> None:
    receipts = (
        _receipt(subject, requested, execution, "release-A", "2026-08-05T00:00:00Z"),
        _receipt(subject, requested, execution, "release-B", "2026-08-06T00:00:00Z"),
    )
    result = assess_resolution_continuity(requested, receipts)
    assert result.outcome == ContinuityOutcome.ALIAS_REBOUND_FOR_SUPPLIED_OBSERVATIONS


def test_same_supplied_resolved_identity_is_observation_scoped(
    subject, requested, execution
) -> None:
    receipts = (
        _receipt(subject, requested, execution, "release-A", "2026-08-05T00:00:00Z"),
        _receipt(subject, requested, execution, "release-A", "2026-08-06T00:00:00Z"),
    )
    result = assess_resolution_continuity(requested, receipts)
    assert result.outcome == ContinuityOutcome.SAME_RESOLVED_IDENTITY_FOR_SUPPLIED_OBSERVATIONS
    assert "continuous" in result.limitations[0].lower()


def test_one_receipt_is_insufficient(subject, requested, execution) -> None:
    receipt = _receipt(subject, requested, execution, "release-A", "2026-08-05T00:00:00Z")
    assert (
        assess_resolution_continuity(requested, (receipt,)).outcome
        == ContinuityOutcome.INSUFFICIENT_OBSERVATIONS
    )


def test_undisclosed_receipt_cannot_claim_resolution(subject, requested, execution) -> None:
    original = _receipt(
        subject, requested, execution, "release-A", "2026-08-05T00:00:00Z"
    ).model_dump(mode="json", by_alias=True)
    original.pop("receipt_id")
    original.pop("receipt_digest")
    original["resolved_identifier"] = None
    changed = finalize_identity(original, "receipt_id", "resolution_receipt_", "receipt_digest")
    with pytest.raises(ValidationError, match="disclosure"):
        RegistryResolutionReceipt.model_validate(changed)


@pytest.mark.parametrize(
    "spelling",
    ["model-2026-08-09", "model-v1", "deadbeef" * 8, "stable", "latest"],
)
def test_identifier_spelling_does_not_infer_immutability(subject, spelling: str) -> None:
    value = build_requested_identifier(
        subject, spelling, kind=IdentifierKind.UNKNOWN_IDENTIFIER_KIND
    )
    assert value.requested_kind == IdentifierKind.UNKNOWN_IDENTIFIER_KIND


def test_provider_api_surface_and_purpose_are_identifier_identity_bearing(subject) -> None:
    common = {"kind": IdentifierKind.MUTABLE_ALIAS, "provider": "provider.synthetic"}
    left = build_requested_identifier(
        subject, "same-slug", api_surface="api.surface.a", purpose="purpose.a", **common
    )
    right = build_requested_identifier(
        subject, "same-slug", api_surface="api.surface.b", purpose="purpose.a", **common
    )
    purpose = build_requested_identifier(
        subject, "same-slug", api_surface="api.surface.a", purpose="purpose.b", **common
    )
    assert len({left.identifier_id, right.identifier_id, purpose.identifier_id}) == 3


def test_resolution_evidence_digest_must_match_exact_reference(
    subject, requested, execution
) -> None:
    with pytest.raises(ValueError, match="evidence digest"):
        build_resolution_receipt(
            subject,
            execution,
            requested,
            status=ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
            resolved="release-A",
            resolved_kind=IdentifierKind.VERSIONED_IDENTIFIER,
            level=ObservationLevel.CALLER_DECLARED,
            evidence_digest="0" * 64,
        )


def test_continuity_requires_comparable_resolution_method(subject, requested, execution) -> None:
    left = _receipt(subject, requested, execution, "release-A", "2026-08-05T00:00:00Z")
    right = build_resolution_receipt(
        subject,
        execution,
        requested,
        status=ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
        resolved="release-B",
        resolved_kind=IdentifierKind.VERSIONED_IDENTIFIER,
        level=ObservationLevel.CALLER_DECLARED,
        mechanism=ResolutionMechanism.REGISTRY_LOOKUP,
        evidence_digest=execution.execution_digest,
        resolved_at="2026-08-06T00:00:00Z",
    )
    assert (
        assess_resolution_continuity(requested, (left, right)).outcome
        == ContinuityOutcome.OBSERVATION_WINDOWS_NOT_COMPARABLE
    )


@pytest.mark.parametrize(
    "available,effective,cutoff,expected",
    [
        (
            "2026-08-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            HistoricalCutoffOutcome.KNOWN_EFFECTIVE_AS_OF_CUTOFF,
        ),
        (
            "2026-08-03T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            HistoricalCutoffOutcome.NOT_KNOWN_AS_OF_CUTOFF,
        ),
        (
            "2026-08-01T00:00:00Z",
            "2026-08-03T00:00:00Z",
            "2026-08-02T00:00:00Z",
            HistoricalCutoffOutcome.KNOWN_FUTURE_EFFECTIVE_AS_OF_CUTOFF,
        ),
        (
            "2026-08-02T00:00:00Z",
            "2026-08-02T00:00:00Z",
            "2026-08-02T00:00:00Z",
            HistoricalCutoffOutcome.KNOWN_EFFECTIVE_AS_OF_CUTOFF,
        ),
        (
            "NOT_RECORDED",
            "2026-08-01T00:00:00Z",
            "2026-08-02T00:00:00Z",
            HistoricalCutoffOutcome.AVAILABILITY_NOT_RECORDED,
        ),
    ],
)
def test_known_as_of_cutoff_uses_availability_not_retrospective_effect(
    available, effective, cutoff, expected
) -> None:
    assert (
        known_as_of_cutoff(available_at=available, effective_at=effective, cutoff=cutoff)
        == expected
    )


@pytest.mark.parametrize(
    "availability,value,digest,length",
    [
        (ContentAvailability.INLINE_SYNTHETIC, "x", None, None),
        (ContentAvailability.DIGEST_ONLY, None, "a" * 64, 7),
        (ContentAvailability.UNAVAILABLE, None, None, None),
    ],
)
def test_independent_content_availability(availability, value, digest, length) -> None:
    identity = content_identity(
        value,
        availability=availability,
        canonicalization_mode="raw.test.bytes",
        media_type="application/octet-stream",
        digest=digest,
        length=length,
    )
    assert identity.availability == availability
    assert (
        "REPRODUCIBLE" in identity.reproducibility
        or availability != ContentAvailability.INLINE_SYNTHETIC
    )


def test_content_digest_domains_are_distinct() -> None:
    text = content_identity(
        "x",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.unicode.text",
        media_type="text/plain",
    )
    binary = content_identity(
        "x",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.output.bytes",
        media_type="application/octet-stream",
    )
    assert text.digest != binary.digest


def test_inline_identity_rejects_wrong_digest() -> None:
    value = content_identity(
        "x",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.unicode.text",
        media_type="text/plain",
    )
    with pytest.raises(ValidationError, match="identity mismatch"):
        value.model_copy(update={"digest": "0" * 64}).__class__.model_validate(
            {**value.model_dump(mode="json"), "digest": "0" * 64}
        )


def test_typed_decimal_reuses_bounded_phase6c_semantics() -> None:
    assert TypedParameter(name="threshold", value_type="DECIMAL", value="1.00").value == "1.00"
    with pytest.raises(ValidationError):
        TypedParameter(name="threshold", value_type="DECIMAL", value="1e999999999")


def test_selected_logit_metric_is_exact_decimal() -> None:
    output = content_identity(
        "x",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.unicode.text",
        media_type="text/plain",
    )
    common = {
        "probe_id": "backend_probe_" + "a" * 32,
        "output": output,
        "token_ids": (),
        "structured_json_digest": None,
        "tool_call_digest": None,
        "finish_reason": None,
        "error_class": None,
        "stream_final_digest": None,
        "stream_chunk_digests": (),
    }
    left = BackendResult(
        **common, selected_logits=(LogitSample(position=0, token_id=1, value="0.1"),)
    )
    right = BackendResult(
        **common, selected_logits=(LogitSample(position=0, token_id=1, value="0.3"),)
    )
    assert selected_logit_max_absolute_error(left, right) == "0.2"


def test_tool_call_order_and_multiplicity_are_identity_bearing() -> None:
    arguments = content_identity(
        '{"city":"Tokyo"}',
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="canonical.json",
        media_type="application/json",
    )
    first = ToolCallRecord(ordinal=0, name="weather", arguments=arguments)
    second = ToolCallRecord(ordinal=1, name="clock", arguments=arguments)
    with pytest.raises(ValidationError, match="tool-call order"):
        BackendResult(
            probe_id="backend_probe_" + "a" * 32,
            output=arguments,
            token_ids=(),
            tool_calls=(second,),
            finish_reason="tool_calls",
            selected_logits=(),
            stream_chunk_digests=(),
        )
    assert first.model_dump(mode="json") != second.model_dump(mode="json")


def test_trusted_authority_cannot_cross_subject_or_self_authorize_purpose() -> None:
    common = {
        "purpose": "runtime.observation",
        "subject_scope": "declared.phase6e.scope",
        "tenant": "tenant.synthetic",
        "project": "project.synthetic",
        "provider": "provider.synthetic",
        "namespace": "namespace.synthetic",
        "trust_domain": "trust-domain.synthetic",
        "context": "audit.explicit",
        "finding": "A trusted key remains scope and purpose constrained.",
    }
    with pytest.raises(ValidationError, match="trust, purpose, and exact subject"):
        AuthorityDimension(
            **common,
            signer_trusted=True,
            authorized=False,
            status="ESTABLISHED",
            authorized_subject_id="model-a",
            evaluated_subject_id="model-a",
        )
    with pytest.raises(ValidationError, match="cross-subject"):
        AuthorityDimension(
            **common,
            signer_trusted=True,
            authorized=True,
            status="ESTABLISHED",
            authorized_subject_id="model-a",
            evaluated_subject_id="model-b",
        )


def test_fake_proof_object_is_rejected(generated: Path) -> None:
    source = json.loads(
        (generated / "runtime-resolution-parity/inference/output-provenance.json").read_bytes()
    )
    source["proof_availability"] = ProofAvailability.PROOF_OBJECT_AVAILABLE.value
    source.pop("provenance_id")
    source.pop("provenance_digest")
    source = finalize_identity(source, "provenance_id", "output_provenance_", "provenance_digest")
    with pytest.raises(ValidationError, match="proof objects"):
        OutputProvenanceEvidence.model_validate(source)


def test_service_signature_cannot_be_labeled_provable_inference(generated: Path) -> None:
    source = json.loads(
        (generated / "runtime-resolution-parity/inference/output-provenance.json").read_bytes()
    )
    source["proof_method"] = "SERVICE_SIGNATURE"
    source["verification_status"] = ProvenanceVerificationStatus.PROVABLE_INFERENCE_NOT_IMPLEMENTED
    source.pop("provenance_id")
    source.pop("provenance_digest")
    source = finalize_identity(source, "provenance_id", "output_provenance_", "provenance_digest")
    with pytest.raises(ValidationError, match="service signature"):
        OutputProvenanceEvidence.model_validate(source)


def test_unsigned_attestation_is_not_serialized_as_verified_service_signature(
    generated: Path,
) -> None:
    attestation = json.loads(
        (generated / "runtime-resolution-parity/inference/inference-attestation.json").read_bytes()
    )
    provenance = json.loads(
        (generated / "runtime-resolution-parity/inference/output-provenance.json").read_bytes()
    )
    assert attestation["method"] == "UNSIGNED_CLAIM"
    assert attestation["signature_report"] is None
    assert provenance["verification_status"] == "WEIGHT_ATTRIBUTION_NOT_ESTABLISHED"


@pytest.mark.parametrize("mismatch", ["request", "output", "runtime"])
def test_proof_reference_must_bind_request_output_and_runtime(
    generated: Path, mismatch: str
) -> None:
    source = json.loads(
        (generated / "runtime-resolution-parity/inference/output-provenance.json").read_bytes()
    )
    reference = ProofReference(
        scheme_identifier="unimplemented.reference",
        scheme_version="unknown",
        reference_digest="1" * 64,
        request_digest=source["request_digest"],
        output_digest=source["output"]["digest"],
        runtime_binding=source["runtime_binding"],
        verifier_identity=None,
        verifier_version=None,
        challenge_digest=None,
        freshness_state="UNAVAILABLE",
        replay_state="UNAVAILABLE",
        authority="NOT_ESTABLISHED",
    ).model_dump(mode="json")
    if mismatch == "request":
        reference["request_digest"] = "2" * 64
    elif mismatch == "output":
        reference["output_digest"] = "2" * 64
    else:
        reference["runtime_binding"]["object_digest"] = "2" * 64
    source.update(
        proof_method="PROVABLE_INFERENCE_PROOF_REFERENCE",
        proof_availability="PROOF_REFERENCE_ONLY",
        proof_reference=reference,
        verification_status="WEIGHT_ATTRIBUTION_NOT_ESTABLISHED",
    )
    source.pop("provenance_id")
    source.pop("provenance_digest")
    source = finalize_identity(source, "provenance_id", "output_provenance_", "provenance_digest")
    with pytest.raises(ValidationError, match="exact request, output, and runtime"):
        OutputProvenanceEvidence.model_validate(source)


def test_exact_finite_outputs_do_not_prove_identical_weights(generated: Path) -> None:
    comparison = json.loads(
        (generated / "runtime-resolution-parity/backends/comparison.json").read_bytes()
    )
    evidence = json.loads((generated / "runtime-resolution-parity/evidence.json").read_bytes())
    assert comparison["status"] == "EXACT_FOR_DECLARED_PROBES"
    assert any("cannot prove identical weights" in item for item in comparison["limitations"])
    assert evidence["status"] == "PARTIAL_FOR_DECLARED_SCOPE"


def test_phase6a_and_phase6d_plus_declaration_do_not_observe_runtime(
    generated: Path,
) -> None:
    base = generated / "runtime-resolution-parity/runtime"
    artifact = RuntimeArtifactExpectation.model_validate(
        json.loads((base / "artifact-expectation.json").read_bytes())
    )
    declaration = DeploymentDeclaration.model_validate(
        json.loads((base / "deployment-declaration.json").read_bytes())
    )
    expectation = RuntimeIdentityExpectation.model_validate(
        json.loads((base / "runtime-expectation.json").read_bytes())
    )
    binding = build_runtime_binding(
        artifact.subject,
        artifact,
        declaration,
        expectation,
        deployment_observation=None,
        runtime_observation=None,
        accepted_strength=expectation.minimum_strength,
        outcome=RuntimeBindingOutcome.EXPECTED_IDENTITY_ONLY,
        policy=build_policy(artifact.subject),
    )
    assert isinstance(binding, ModelRuntimeBinding)
    assert binding.runtime_observation is None
    assert binding.outcome != RuntimeBindingOutcome.RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE


def test_digest_only_plaintext_is_absent_from_generated_evidence(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime-resolution-parity/inference/inference-identity.json").read_bytes()
    )
    assert value["request"]["availability"] == "DIGEST_ONLY"
    assert value["request"]["inline_synthetic"] is None
    assert value["output"]["inline_synthetic"] is None


@pytest.mark.parametrize(
    "character",
    ["\x00", "\x1b", "\x85", "\u200d", "\u202e", "\u2066", "#", "`", "|"],
)
def test_report_text_escapes_controls_bidi_and_markdown(character: str) -> None:
    rendered = safe_text("before" + character + "after")
    if character in "#`|":
        assert "\\" + character in rendered
    else:
        assert character not in rendered


def test_xai_profile_is_documentation_only(subject) -> None:
    statements, readiness = build_xai_practice(Path.cwd(), subject)
    assert all(value.statement_kind == "PROVIDER_DOCUMENTED_ROUTING_POLICY" for value in statements)
    assert readiness.production_request == "NOT_PERFORMED"
    assert readiness.api_response == "NOT_OBSERVED"
    assert readiness.runtime_identity == "NOT_OBSERVED"
    assert readiness.weight_identity == "NOT_OBSERVED"
    assert all(
        rule.mechanism != ResolutionMechanism.HTTP_REDIRECT
        for statement in statements
        for rule in statement.rules
    )


def test_anthropic_profile_is_roadmap_only(subject) -> None:
    statement, readiness = build_anthropic_practice(Path.cwd(), subject)
    assert statement.statement_kind == "PROVIDER_RESEARCH_ROADMAP_STATEMENT"
    assert readiness.prototype == "PROTOTYPE_NOT_OBSERVED"
    assert readiness.proof_format == "PUBLIC_PROOF_FORMAT_NOT_SUPPLIED"
    assert readiness.implementation == "PROVABLE_INFERENCE_NOT_IMPLEMENTED"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_public_document_fixture_is_pinned(name: str) -> None:
    source, fixture_digest = load_public_document_fixture(Path.cwd(), name)
    assert source.human_review_status == "REVIEWED"
    assert len(fixture_digest) == 64
    assert source.response_body_sha256 == EXPECTED[name][0]
    assert source.content_length == EXPECTED[name][1]
    assert source.retrieval_method == "GET"
    assert source.head_request_count == source.get_request_count == 1
    assert all(claim.body_region_sha256 for claim in source.claims)


def test_public_document_capture_accounting_is_exact() -> None:
    sources = [load_public_document_fixture(Path.cwd(), name)[0] for name in sorted(EXPECTED)]
    assert sum(source.head_request_count for source in sources) == 3
    assert sum(source.get_request_count for source in sources) == 3
    assert sum(source.content_length for source in sources) == 1_158_612


def test_offline_public_document_regions_match_retained_raw_bodies_when_available() -> None:
    raw_paths = {
        "xai-release-notes.normalized.json": Path("/tmp/omiv-phase6e-xai-release-notes.html"),
        "xai-may-15-retirement.normalized.json": Path("/tmp/omiv-phase6e-xai-retirement.html"),
        "anthropic-roadmap.normalized.json": Path("/tmp/omiv-phase6e-anthropic-roadmap.html"),
    }
    for name, raw_path in raw_paths.items():
        if not raw_path.exists():
            continue
        source, _digest = load_public_document_fixture(Path.cwd(), name)
        raw = raw_path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == source.response_body_sha256
        assert len(raw) == source.content_length
        for claim in source.claims:
            region = raw[claim.body_byte_start : claim.body_byte_start + claim.body_byte_length]
            assert hashlib.sha256(region).hexdigest() == claim.body_region_sha256


def test_public_fixtures_contain_no_page_body() -> None:
    for path in Path("fixtures/runtime-resolution/public-documents").glob("*.json"):
        value = json.loads(path.read_bytes())
        assert "body" not in value
        assert "html" not in value


def test_scenario_catalog_has_distinct_required_cases(generated: Path) -> None:
    assert len(SCENARIOS) == 53
    values = [
        json.loads(path.read_bytes())
        for path in sorted((generated / "runtime-resolution-parity/scenarios").glob("*.json"))
    ]
    assert len(values) == len(SCENARIOS)
    assert len({item["result_id"] for item in values}) == len(SCENARIOS)
    assert len({item["result_digest"] for item in values}) == len(SCENARIOS)
    required = {
        "semantic-rerouting",
        "incomparable-resolution-methods",
        "tool-call-mismatch",
        "finish-reason-mismatch",
        "digest-only-request",
        "digest-only-output",
        "proof-request-mismatch",
        "proof-output-mismatch",
        "proof-runtime-mismatch",
        "authority-model-a-vs-b",
        "phase6c-boundary",
    }
    assert required <= {item["case_id"] for item in values}


def test_generated_content_and_canonical_ids_are_unique(generated: Path) -> None:
    index = json.loads((generated / "runtime-resolution-parity/artifact-index.json").read_bytes())
    assert len(index["entries"]) == 114
    assert len({item["sha256"] for item in index["entries"]}) == 114
    assert len({item["canonical_id"] for item in index["entries"]}) == 114


def test_artifact_index_is_external_and_complete(generated: Path) -> None:
    index = load_runtime_resolution(
        generated / "runtime-resolution-parity/artifact-index.json",
        RuntimeResolutionArtifactIndex,
    )
    assert isinstance(index, RuntimeResolutionArtifactIndex)
    assert all(
        item.path != "runtime-resolution-parity/artifact-index.json" for item in index.entries
    )
    verify_runtime_resolution_artifact_index(generated, index)


def test_representative_signatures_verify(generated: Path) -> None:
    base = generated / "runtime-resolution-parity/signed"
    policy = TrustPolicy.model_validate(json.loads((base / "trust-policy.json").read_bytes()))
    bundle = TrustBundle.model_validate(json.loads((base / "trust-bundle.json").read_bytes()))
    envelopes = sorted(base.glob("*.envelope.json"))
    assert len(envelopes) == 3
    for path in envelopes:
        envelope = SignedObjectEnvelope.model_validate(json.loads(path.read_bytes()))
        report = verify_envelope(envelope, bundle, policy)
        assert report.signature_results[0].signature_integrity.value == "VALID"
        assert report.underlying_claim.get("weight_attribution_proven") is False


def test_only_representative_classes_are_signed(generated: Path) -> None:
    types = {
        json.loads(path.read_bytes())["signed_object_type"]
        for path in (generated / "runtime-resolution-parity/signed").glob("*.envelope.json")
    }
    assert types == {
        "REGISTRY_RESOLUTION_RECEIPT",
        "MODEL_RUNTIME_BINDING",
        "RUNTIME_RESOLUTION_PARITY_EVIDENCE",
    }


def test_two_run_generation_is_byte_identical(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    generate_all_runtime_resolution_examples(left, repository=Path.cwd())
    generate_all_runtime_resolution_examples(right, repository=Path.cwd())
    left_paths = sorted(path.relative_to(left) for path in left.rglob("*") if path.is_file())
    right_paths = sorted(path.relative_to(right) for path in right.rglob("*") if path.is_file())
    assert left_paths == right_paths
    assert all((left / path).read_bytes() == (right / path).read_bytes() for path in left_paths)


def test_workspace_generation_matches_fresh_generation(generated: Path) -> None:
    for path in (generated / "runtime-resolution-parity").rglob("*"):
        if path.is_file():
            relative = path.relative_to(generated)
            assert path.read_bytes() == relative.read_bytes()
    for path in (generated / "reports/runtime-resolution-parity").rglob("*"):
        if path.is_file():
            relative = path.relative_to(generated)
            assert path.read_bytes() == relative.read_bytes()


def test_no_implicit_time_in_generated_json(generated: Path) -> None:
    raw = b"".join(path.read_bytes() for path in generated.rglob("*.json"))
    assert b"2026-08-09" not in raw
    assert b"NOT_RECORDED" in raw


def test_core_imports_no_provider_profiles() -> None:
    raw = b"\n".join(
        line
        for path in Path("src/omiv/runtime_resolution").glob("*.py")
        for line in path.read_bytes().splitlines()
        if line.lstrip().startswith((b"import ", b"from "))
    )
    for forbidden in (b"runtime_resolution_profiles", b"xai", b"grok", b"anthropic"):
        assert forbidden not in raw.lower()


def test_no_model_or_template_execution_path() -> None:
    raw = b"".join(
        path.read_bytes()
        for root in (
            Path("src/omiv/runtime_resolution"),
            Path("src/omiv/runtime_resolution_profiles"),
        )
        for path in root.glob("*.py")
    ).lower()
    for forbidden in (
        b"trust_remote_code",
        b"apply_chat_template",
        b"pickle.loads",
        b"subprocess.run",
        b"importlib.import_module",
    ):
        assert forbidden not in raw


def test_preservation_audit_matches_baseline() -> None:
    result = audit_baseline(Path.cwd())
    assert result["baseline_revision"] == BASELINE
    assert result["changed_paths"] == []
    assert result["missing_paths"] == []
    assert result["unexpected_omissions"] == []
    assert result["counts"]["included"] == 897


def test_ignored_kimi_artifact_identity() -> None:
    observation = observe_external_artifact(Path.cwd(), KIMI_K3_TENSOR_INVENTORY)
    assert observation.expected.identity_status == (
        ExternalArtifactStatus.EXPECTED_IDENTITY_RECORDED
    )
    assert observation.status in {
        ExternalArtifactStatus.PRESENT_AND_VERIFIED,
        ExternalArtifactStatus.NOT_AVAILABLE,
    }
    if observation.available:
        assert observation.observed_size_bytes == 115_542_096
        assert observation.observed_sha256 == KIMI_K3_TENSOR_INVENTORY.sha256
    else:
        assert observation.observed_size_bytes is None
        assert observation.observed_sha256 is None
