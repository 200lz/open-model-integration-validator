"""Deterministic offline Phase 6E examples and practice evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubject, ProductSubjectClass
from omiv.runtime_resolution.building import (
    build_artifact_expectation,
    build_assumption,
    build_authority_evaluation,
    build_backend,
    build_backend_execution,
    build_backend_plan,
    build_catalog,
    build_deployment_declaration,
    build_deployment_observation,
    build_evidence,
    build_identifier_classification,
    build_inference_attestation,
    build_inference_identity,
    build_integration,
    build_output_provenance,
    build_policy,
    build_policy_evaluation,
    build_probe_definition,
    build_probe_set,
    build_report,
    build_requested_identifier,
    build_resolution_execution,
    build_resolution_plan,
    build_resolution_receipt,
    build_result_observation,
    build_runtime_binding,
    build_runtime_expectation,
    build_runtime_observation,
    build_scenario,
)
from omiv.runtime_resolution.comparison import compare_backend_results
from omiv.runtime_resolution.models import (
    IDENTITY_SPECS,
    AssumptionStatus,
    AttestationMethod,
    AuthorityDimension,
    AuthorityStatus,
    BackendResult,
    ContentAvailability,
    EvidenceStatus,
    ExecutionMode,
    IdentifierKind,
    LogitSample,
    ObjectReference,
    ObservationLevel,
    ObservationStrength,
    PolicyRequirement,
    ProofAvailability,
    ProvenanceVerificationStatus,
    RequirementStatus,
    ResolutionStatus,
    ResultDimension,
    RuntimeBindingOutcome,
    RuntimeResolutionArtifactIndex,
    RuntimeResolutionArtifactIndexEntry,
    content_identity,
    finalize_identity,
    object_reference,
)
from omiv.runtime_resolution.reporting import pretty_json, render_markdown
from omiv.runtime_resolution.resolution import assess_resolution_continuity
from omiv.runtime_resolution_profiles.anthropic import build_anthropic_practice
from omiv.runtime_resolution_profiles.models import (
    AnthropicProvableInferenceReadiness,
    XaiRuntimeResolutionReadiness,
)
from omiv.runtime_resolution_profiles.xai import build_xai_practice
from omiv.safe_write import atomic_write_text
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


def _external(schema: str, identity: str, seed: str) -> ObjectReference:
    return ObjectReference(
        schema_id=schema,
        object_id=identity,
        object_digest=canonical_sha256({"external-reference": seed}),
    )


def _write(root: Path, relative: str, value: BaseModel) -> None:
    path = root / "runtime-resolution-parity" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, pretty_json(value))


def _signed_examples(
    receipt: BaseModel, binding: BaseModel, evidence: BaseModel
) -> list[tuple[str, BaseModel]]:
    types = [
        SignedObjectType.REGISTRY_RESOLUTION_RECEIPT,
        SignedObjectType.MODEL_RUNTIME_BINDING,
        SignedObjectType.RUNTIME_RESOLUTION_PARITY_EVIDENCE,
    ]
    purposes = [
        SignaturePurpose.REGISTRY_RESOLUTION_RECEIPT_ISSUANCE,
        SignaturePurpose.MODEL_RUNTIME_BINDING_ISSUANCE,
        SignaturePurpose.RUNTIME_RESOLUTION_PARITY_EVIDENCE_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([110]) * 32)
    key = build_key_identity(private, allowed_object_types=types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic runtime-resolution evidence issuer",
        role="RUNTIME_RESOLUTION_EVIDENCE_ISSUER",
        evidence=[hashlib.sha256(b"omiv-phase6e-synthetic-issuer").hexdigest()],
        verification_status="EVIDENCE_LINKED",
    )
    binding_record = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)],
        [key],
        identities=[signer],
        bindings=[binding_record],
    )
    output: list[tuple[str, BaseModel]] = [
        ("signed/trust-policy.json", policy),
        ("signed/trust-bundle.json", bundle),
    ]
    for name, value, object_type, purpose in (
        ("resolution-receipt", receipt, types[0], purposes[0]),
        ("runtime-binding", binding, types[1], purposes[1]),
        ("evidence", evidence, types[2], purposes[2]),
    ):
        raw = value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
        signature = build_signature_record(
            descriptor, private, key, binding_id=binding_record.binding_id
        )
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        output.append((f"signed/{name}.envelope.json", envelope))
        if name != "evidence":
            output.append(
                (f"signed/{name}.signature-report.json", verify_envelope(envelope, bundle, policy))
            )
    return output


SCENARIOS = (
    ("immutable-pinned", "Pinned spelling is explicitly classified.", "RECORDED"),
    ("mutable-unobserved", "Mutable alias without receipt remains unresolved.", "NOT_EVALUATED"),
    ("alias-same-target", "Comparable supplied receipts retain the same target.", "SAME_TARGET"),
    ("alias-rebound", "Comparable supplied receipts disclose changed targets.", "ALIAS_REBOUND"),
    ("deprecated-resolves", "Deprecated identifier resolution stays receipt scoped.", "RECORDED"),
    ("redirect-changed", "Changed redirect targets remain observation scoped.", "REDIRECT_CHANGED"),
    (
        "semantic-rerouting",
        "Provider semantic routing remains distinct from an HTTP redirect.",
        "DOCUMENTED_ONLY",
    ),
    (
        "incomparable-resolution-methods",
        "Different resolution methods cannot establish continuity.",
        "NOT_COMPARABLE",
    ),
    ("undisclosed-resolution", "Undisclosed identity cannot be upgraded.", "INSUFFICIENT"),
    (
        "documented-not-runtime",
        "Provider documentation is not runtime observation.",
        "NOT_OBSERVED",
    ),
    ("future-effective", "Future effectiveness is distinct from observation.", "NOT_OBSERVED"),
    ("late-arriving", "Late evidence follows KNOWN_AS_OF_CUTOFF.", "LATE_EVIDENCE"),
    ("expected-deployment", "Expected deployment is not observed deployment.", "EXPECTED_ONLY"),
    ("control-plane", "Control-plane evidence retains its strength.", "CONTROL_PLANE_ONLY"),
    ("self-report", "Runtime self-report is not direct weight observation.", "SELF_REPORTED"),
    ("local-artifact", "Exact local artifact observation is scope qualified.", "LOCAL_BINDING"),
    ("runtime-mismatch", "Observed and expected identity mismatch remains visible.", "MISMATCH"),
    ("runtime-strength", "Insufficient observation strength fails closed.", "INSUFFICIENT"),
    (
        "deterministic-exact",
        "Exact supplied deterministic results are probe scoped.",
        "EXACT_PROBES",
    ),
    ("text-mismatch", "Text mismatch is dimension specific.", "MISMATCH"),
    ("token-id-mismatch", "Token ID mismatch is dimension specific.", "MISMATCH"),
    (
        "tool-call-mismatch",
        "Tool-call names, arguments, order, and count are compared.",
        "MISMATCH",
    ),
    ("finish-reason-mismatch", "Finish-reason mismatch remains dimension specific.", "MISMATCH"),
    ("json-exact", "Canonical structured JSON identity may match.", "EXACT_PROBES"),
    ("json-mismatch", "Structured JSON mismatch remains visible.", "MISMATCH"),
    ("stream-boundaries", "Equal aggregate differs from chunk boundaries.", "PARTIAL"),
    ("stochastic", "Stochastic samples are not directly comparable by default.", "NOT_COMPARABLE"),
    ("logit-pass", "Selected-logit tolerance is sample scoped.", "WITHIN_TOLERANCE"),
    ("logit-fail", "Selected-logit tolerance failures remain visible.", "OUTSIDE_TOLERANCE"),
    ("finite-probe-scope", "Finite probes cannot establish complete parity.", "PROBE_SCOPED"),
    ("output-not-weights", "Exact output does not prove identical weights.", "NOT_PROVEN"),
    ("digest-only", "Request and output plaintext can remain unavailable.", "DIGEST_ONLY"),
    (
        "digest-only-request",
        "Digest-only request content is not inspectable plaintext.",
        "DIGEST_ONLY",
    ),
    (
        "digest-only-output",
        "Digest-only output content is not inspectable plaintext.",
        "DIGEST_ONLY",
    ),
    ("service-signature", "Service signature is not weight attribution.", "CLAIM_ONLY"),
    (
        "provider-reference",
        "Provider attestation reference is not independently verified.",
        "REFERENCE_ONLY",
    ),
    ("tee-reference", "TEE reference remains not evaluated.", "NOT_EVALUATED"),
    ("proof-format", "Unavailable proof format remains unavailable.", "UNAVAILABLE"),
    ("fake-proof", "Signature substitution for proof is rejected.", "INVALID"),
    ("proof-request-mismatch", "Proof reference with a mismatched request is rejected.", "INVALID"),
    ("proof-output-mismatch", "Proof reference with a mismatched output is rejected.", "INVALID"),
    ("proof-runtime-mismatch", "Proof reference with a mismatched runtime is rejected.", "INVALID"),
    ("service-key-scope", "Service key lacks weight-attribution authority.", "NOT_AUTHORIZED"),
    ("authority-model-a-vs-b", "Model-A authority cannot authorize model B.", "NOT_AUTHORIZED"),
    ("phase6a-boundary", "Exact bytes alone do not observe runtime identity.", "NOT_OBSERVED"),
    (
        "phase6c-boundary",
        "Quantization fidelity does not observe runtime identity.",
        "NOT_OBSERVED",
    ),
    (
        "phase6d-boundary",
        "Tokenizer parity alone does not observe runtime weights.",
        "NOT_OBSERVED",
    ),
    ("xai-mutable", "xAI alias evidence is provider-document scoped.", "DOCUMENTED_ONLY"),
    ("xai-redirect", "xAI redirect evidence is provider-document scoped.", "DOCUMENTED_ONLY"),
    ("anthropic-roadmap", "Roadmap signal is not prototype completion.", "ROADMAP_ONLY"),
    (
        "assumption-invalidated",
        "Mutable routing invalidates stable-slug assumption.",
        "INVALIDATED",
    ),
    (
        "assumption-weakened",
        "Artifact identity and inference attribution are separate.",
        "WEAKENED",
    ),
    ("limit-exceeded", "Resource limits fail deterministically.", "LIMIT_EXCEEDED"),
)


def generate_all_runtime_resolution_examples(
    output_root: Path, *, repository: Path | None = None
) -> RuntimeResolutionArtifactIndex:
    repository = (repository or Path.cwd()).resolve()
    output_root = output_root.resolve()
    subject = build_product_subject(
        ProductSubjectClass.DEPLOYMENT_PACKAGE,
        "runtime-resolution.phase6e-synthetic",
        synthetic_scope(project="project.runtime-resolution", environment="environment.offline"),
    )
    requested = build_requested_identifier(
        subject, "synthetic-runtime-latest", kind=IdentifierKind.MUTABLE_ALIAS
    )
    classification = build_identifier_classification(
        subject, requested, kind=IdentifierKind.MUTABLE_ALIAS
    )
    plan = build_resolution_plan(subject, requested, classification)
    execution = build_resolution_execution(subject, plan)
    receipts = (
        build_resolution_receipt(
            subject,
            execution,
            requested,
            status=ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
            resolved="synthetic-model-A",
            resolved_kind=IdentifierKind.VERSIONED_IDENTIFIER,
            level=ObservationLevel.CALLER_DECLARED,
            evidence_digest=execution.execution_digest,
            resolved_at="2026-08-05T00:00:00Z",
        ),
        build_resolution_receipt(
            subject,
            execution,
            requested,
            status=ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
            resolved="synthetic-model-B",
            resolved_kind=IdentifierKind.VERSIONED_IDENTIFIER,
            level=ObservationLevel.CALLER_DECLARED,
            evidence_digest=execution.execution_digest,
            resolved_at="2026-08-06T00:00:00Z",
        ),
    )
    continuity = assess_resolution_continuity(requested, receipts)
    payload_ref = _external(
        "omiv.observed-payload-manifest.v1",
        "manifest_" + canonical_sha256({"phase": "6a"})[:32],
        "phase6a.payload",
    )
    tokenizer_ref = _external(
        "omiv.tokenizer-configuration-parity-evidence.v1",
        "tokenizer_configuration_evidence_" + canonical_sha256({"phase": "6d"})[:32],
        "phase6d.tokenizer",
    )
    artifact = build_artifact_expectation(
        subject, payload_ref, payload_identity=payload_ref, tokenizer_identity=tokenizer_ref
    )
    declaration = build_deployment_declaration(subject, artifact)
    deployment = build_deployment_observation(
        subject,
        declaration,
        execution,
        artifact,
        strength=ObservationStrength.FILESYSTEM_ARTIFACT_OBSERVATION,
        local_artifact=payload_ref,
    )
    runtime_expectation = build_runtime_expectation(
        subject,
        declaration,
        artifact,
        minimum_strength=ObservationStrength.FILESYSTEM_ARTIFACT_OBSERVATION,
    )
    runtime_observation = build_runtime_observation(
        subject,
        deployment,
        runtime_expectation,
        observed_identity=payload_ref,
        strength=ObservationStrength.FILESYSTEM_ARTIFACT_OBSERVATION,
    )
    policy = build_policy(subject)
    binding = build_runtime_binding(
        subject,
        artifact,
        declaration,
        runtime_expectation,
        deployment_observation=deployment,
        runtime_observation=runtime_observation,
        accepted_strength=ObservationStrength.FILESYSTEM_ARTIFACT_OBSERVATION,
        outcome=RuntimeBindingOutcome.RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE,
        policy=policy,
    )
    binding_partial = build_runtime_binding(
        subject,
        artifact,
        declaration,
        runtime_expectation,
        deployment_observation=deployment,
        runtime_observation=runtime_observation,
        accepted_strength=ObservationStrength.CONTROL_PLANE_CONFIGURATION,
        outcome=RuntimeBindingOutcome.INSUFFICIENT_OBSERVATION,
        policy=policy,
    )
    backends = (
        build_backend(subject, "backend.synthetic.a", binding, tokenizer_identity=tokenizer_ref),
        build_backend(
            subject, "backend.synthetic.b", binding_partial, tokenizer_identity=tokenizer_ref
        ),
    )
    request_inline = content_identity(
        "Harmless synthetic prompt.",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.unicode.text",
        media_type="text/plain",
    )
    output_inline = content_identity(
        "Harmless synthetic output.",
        availability=ContentAvailability.INLINE_SYNTHETIC,
        canonicalization_mode="raw.unicode.text",
        media_type="text/plain",
    )
    probe = build_probe_definition(
        kind="text.generation.supplied",
        input_identity=request_inline,
        binding=binding,
        dimensions=(
            ResultDimension.FINAL_TEXT,
            ResultDimension.TOKEN_ID_SEQUENCE,
            ResultDimension.STRUCTURED_JSON,
            ResultDimension.SELECTED_LOGIT_SAMPLES,
            ResultDimension.STREAM_FINAL_AGGREGATE,
            ResultDimension.STREAM_CHUNK_BOUNDARIES,
        ),
        mode=ExecutionMode.DECLARED_DETERMINISTIC,
        seed=7,
        tokenizer_identity=tokenizer_ref,
    )
    probe_set = build_probe_set(subject, (probe,))
    plans = tuple(
        build_backend_plan(subject, probe_set, backend, selected_binding)
        for backend, selected_binding in zip(backends, (binding, binding_partial), strict=True)
    )
    executions = tuple(
        build_backend_execution(subject, backend_plan, backend, selected_binding, probe_set)
        for backend_plan, backend, selected_binding in zip(
            plans, backends, (binding, binding_partial), strict=True
        )
    )
    structured = canonical_sha256({"synthetic": {"answer": 1}})
    result = BackendResult(
        probe_id=probe.probe_id,
        output=output_inline,
        token_ids=(7, 11, 13),
        structured_json_digest=structured,
        tool_call_digest=None,
        finish_reason="stop",
        selected_logits=(LogitSample(position=0, token_id=7, value="0.125", rank=1),),
        error_class=None,
        stream_final_digest=output_inline.digest,
        stream_chunk_digests=(canonical_sha256({"chunk": 0}),),
    )
    observations = tuple(
        build_result_observation(
            subject, execution_record, backend, selected_binding, probe_set, (result,)
        )
        for execution_record, backend, selected_binding in zip(
            executions, backends, (binding, binding_partial), strict=True
        )
    )
    comparison = compare_backend_results(
        probe_set, (binding, binding_partial), observations, policy=policy
    )
    digest_request = content_identity(
        None,
        availability=ContentAvailability.DIGEST_ONLY,
        canonicalization_mode="raw.prompt.bytes",
        media_type="application/octet-stream",
        digest=canonical_sha256({"private-request": "not-stored"}),
        length=37,
    )
    digest_output = content_identity(
        None,
        availability=ContentAvailability.DIGEST_ONLY,
        canonicalization_mode="raw.output.bytes",
        media_type="application/octet-stream",
        digest=canonical_sha256({"private-output": "not-stored"}),
        length=41,
    )
    inference = build_inference_identity(
        subject,
        requested,
        binding,
        executions[0],
        observations[0],
        digest_request,
        digest_output,
        receipt=receipts[1],
    )
    attestation = build_inference_attestation(
        subject, inference, binding, method=AttestationMethod.UNSIGNED_CLAIM
    )
    authority_evaluation = build_authority_evaluation(
        subject,
        policy,
        (
            AuthorityDimension(
                purpose="service.output.claim",
                signer_trusted=True,
                authorized=True,
                status=AuthorityStatus.ESTABLISHED,
                subject_scope="declared.phase6e.scope",
                authorized_subject_id=subject.subject_id,
                evaluated_subject_id=subject.subject_id,
                tenant="tenant.synthetic",
                project="project.runtime-resolution",
                provider="provider.synthetic",
                namespace="namespace.synthetic",
                trust_domain="trust-domain.synthetic",
                context="synthetic.explicit",
                finding="Service-origin authority does not include weight attribution.",
            ),
            AuthorityDimension(
                purpose="weight.attribution",
                signer_trusted=True,
                authorized=False,
                status=AuthorityStatus.NOT_ESTABLISHED,
                subject_scope="declared.phase6e.scope",
                authorized_subject_id=subject.subject_id,
                evaluated_subject_id=subject.subject_id,
                tenant="tenant.synthetic",
                project="project.runtime-resolution",
                provider="provider.synthetic",
                namespace="namespace.synthetic",
                trust_domain="trust-domain.synthetic",
                context="synthetic.explicit",
                finding="The service key is not authorized for weight-attribution claims.",
            ),
        ),
        status=AuthorityStatus.NOT_ESTABLISHED,
    )
    provenance = build_output_provenance(
        subject,
        inference,
        attestation,
        binding,
        proof_method=AttestationMethod.UNSIGNED_CLAIM,
        proof_availability=ProofAvailability.PROOF_UNAVAILABLE,
        verification_status=ProvenanceVerificationStatus.WEIGHT_ATTRIBUTION_NOT_ESTABLISHED,
        policy=policy,
        authority_evaluation=authority_evaluation,
    )
    policy_evaluation = build_policy_evaluation(
        subject,
        policy,
        binding,
        comparison=comparison,
        provenance=provenance,
        requirements=(
            PolicyRequirement(
                requirement="runtime.observation.strength",
                status=RequirementStatus.SATISFIED,
                finding="Exact local artifact identity is bound for the declared scope.",
            ),
            PolicyRequirement(
                requirement="weight.attribution",
                status=RequirementStatus.NOT_EVALUATED,
                finding="No weight-attributable inference proof is available.",
            ),
        ),
        status=RequirementStatus.NOT_EVALUATED,
    )
    evidence = build_evidence(
        subject,
        continuity,
        binding,
        comparison,
        provenance,
        policy_evaluation,
        authority_evaluation,
        status=EvidenceStatus.PARTIAL_FOR_DECLARED_SCOPE,
    )
    xai_statements, xai = build_xai_practice(repository, subject)
    anthropic_statement, anthropic = build_anthropic_practice(repository, subject)
    assumptions = (
        build_assumption(
            subject,
            statement="stable API model identifier identifies a stable model release",
            status=AssumptionStatus.INVALIDATED,
            evidence=(object_reference(xai_statements[0]), object_reference(xai_statements[1])),
            strength=ObservationLevel.PROVIDER_DOCUMENTED_POLICY,
            boundary="identifier.resolution",
            schemas=("omiv.requested-model-identifier.v1", "omiv.registry-resolution-receipt.v1"),
            policy=policy,
            basis="Provider documentation demonstrates mutable aliases and redirects.",
        ),
        build_assumption(
            subject,
            statement="verified artifact identity is sufficient to prove runtime model identity",
            status=AssumptionStatus.WEAKENED,
            evidence=(object_reference(binding), object_reference(provenance)),
            strength=ObservationLevel.CALLER_DECLARED,
            boundary="runtime.weight.attribution",
            schemas=("omiv.model-runtime-binding.v1", "omiv.output-provenance-evidence.v1"),
            policy=policy,
            basis=(
                "Artifact/deployment verification and weight-attributable inference "
                "are separate trust boundaries."
            ),
        ),
    )
    integrations = tuple(
        build_integration(
            subject,
            evidence,
            phase=phase,
            state=state,
            upstream=(
                payload_ref if phase == "phase6a" else tokenizer_ref if phase == "phase6d" else None
            ),
        )
        for phase, state in (
            ("phase5a", "derived.summary.only"),
            ("phase5b", "append.only.reference"),
            ("phase5c", "claims.remain.claims"),
            ("phase5d", "existing.trust.reused"),
            ("phase5e", "no.automatic.approval"),
            ("phase5f", "security.not.established"),
            ("phase5g", "runtime.evidence.downstream"),
            ("phase5h", "known.as.of.cutoff"),
            ("phase6a", "payload.identity.authority"),
            ("phase6c", "weight.fidelity.independent"),
            ("phase6d", "tokenizer.parity.independent"),
        )
    )
    scenario_upstream = (
        object_reference(receipts[0]),
        object_reference(receipts[1]),
        object_reference(binding),
        object_reference(comparison),
        object_reference(provenance),
        object_reference(xai),
        object_reference(anthropic),
    )
    scenarios = tuple(
        build_scenario(
            subject,
            case_id=case_id,
            invariant=invariant,
            outcome=outcome,
            findings=(f"{case_id}:{outcome}",),
            upstream=(scenario_upstream[index % len(scenario_upstream)],),
        )
        for index, (case_id, invariant, outcome) in enumerate(SCENARIOS)
    )
    catalog = build_catalog(subject, scenarios)
    report = build_report(
        subject,
        evidence,
        (
            "Requested identifier differs from resolved release and runtime weight identity.",
            "Provider documentation is not an observed production request.",
            "Service signature validity is not weight attribution.",
            "Finite supplied backend results remain probe scoped.",
            "OMIV Phase 6E does not implement provable inference.",
        ),
    )
    objects: list[tuple[str, BaseModel]] = [
        ("requested-identifier.json", requested),
        ("identifier-classification.json", classification),
        ("resolution-plan.json", plan),
        ("resolution-execution.json", execution),
        ("receipts/t0.json", receipts[0]),
        ("receipts/t1.json", receipts[1]),
        ("resolution-continuity.json", continuity),
        ("runtime/artifact-expectation.json", artifact),
        ("runtime/deployment-declaration.json", declaration),
        ("runtime/deployment-observation.json", deployment),
        ("runtime/runtime-expectation.json", runtime_expectation),
        ("runtime/runtime-observation.json", runtime_observation),
        ("runtime/runtime-binding.json", binding),
        ("runtime/runtime-binding-partial.json", binding_partial),
        ("backends/backend-a.json", backends[0]),
        ("backends/backend-b.json", backends[1]),
        ("backends/probe-set.json", probe_set),
        ("backends/plan-a.json", plans[0]),
        ("backends/plan-b.json", plans[1]),
        ("backends/execution-a.json", executions[0]),
        ("backends/execution-b.json", executions[1]),
        ("backends/result-a.json", observations[0]),
        ("backends/result-b.json", observations[1]),
        ("backends/comparison.json", comparison),
        ("inference/inference-identity.json", inference),
        ("inference/inference-attestation.json", attestation),
        ("inference/output-provenance.json", provenance),
        ("policy/policy.json", policy),
        ("policy/evaluation.json", policy_evaluation),
        ("policy/authority.json", authority_evaluation),
        ("evidence.json", evidence),
        ("assumptions/stable-api-identifier.json", assumptions[0]),
        ("assumptions/artifact-runtime-identity.json", assumptions[1]),
        ("practice/xai-release-routing.json", xai_statements[0]),
        ("practice/xai-retirement-routing.json", xai_statements[1]),
        ("practice/xai-readiness.json", xai),
        ("practice/anthropic-roadmap-statement.json", anthropic_statement),
        ("practice/anthropic-readiness.json", anthropic),
        ("scenario-catalog.json", catalog),
        ("report.json", report),
    ]
    objects.extend((f"integrations/{value.phase}.json", value) for value in integrations)
    objects.extend((f"scenarios/{value.case_id}.json", value) for value in scenarios)
    objects.extend(_signed_examples(receipts[1], binding, evidence))
    for relative, value in objects:
        _write(output_root, relative, value)
    report_root = output_root / "reports" / "runtime-resolution-parity"
    report_root.mkdir(parents=True, exist_ok=True)
    atomic_write_text(report_root / "synthetic-evidence.md", render_markdown(report))
    atomic_write_text(report_root / "xai-runtime-resolution-case-study.md", _xai_markdown(xai))
    atomic_write_text(
        report_root / "anthropic-provable-inference-roadmap.md", _anthropic_markdown(anthropic)
    )
    index = _rebuild_index(output_root, subject)
    atomic_write_text(
        output_root / "runtime-resolution-parity" / "artifact-index.json",
        pretty_json(index),
    )
    return index


def _xai_markdown(value: XaiRuntimeResolutionReadiness) -> str:
    return (
        "# xAI runtime-resolution readiness\n\n"
        f"Classification: `{value.classification}`\n\n"
        "A model name is not a model identity. This is an evidence-model principle, not a claim "
        "that every identifier is mutable. Reviewed provider documentation records routing policy; "
        "its model rerouting is provider-semantic routing, not an observed HTTP redirect. "
        "OMIV made no production request and observed no API response, artifact, runtime, "
        "or weights.\n"
    )


def _anthropic_markdown(value: AnthropicProvableInferenceReadiness) -> str:
    return (
        "# Anthropic provable-inference roadmap readiness\n\n"
        f"Classification: `{value.classification}`\n\n"
        "The reviewed public roadmap records a September 30, 2026 target and distinguishes "
        "intended model-version verification from output attribution to specified weights. "
        "The evidence layers "
        "remain: signed artifact → verified deployment → observed runtime binding → inference "
        "attestation → provable weight attribution. No prototype, public proof format, "
        "verifier, or "
        "provable-inference implementation was observed.\n"
    )


def _canonical_id(value: dict[str, object]) -> str:
    fields = {schema: identity[0] for schema, identity in IDENTITY_SPECS.items()}
    fields.update(
        {
            "omiv.xai-runtime-resolution-readiness.v1": "readiness_id",
            "omiv.anthropic-provable-inference-readiness.v1": "readiness_id",
            "omiv.signed-object-envelope.v1": "envelope_id",
            "omiv.signature-report.v1": "report_id",
            "omiv.trust-policy.v1": "policy_id",
            "omiv.trust-bundle.v1": "bundle_id",
        }
    )
    schema = str(value.get("schema"))
    field = fields.get(schema)
    if field is None or not isinstance(value.get(field), str):
        raise ValueError(f"generated Phase 6E object lacks canonical identity: {schema}")
    return str(value[field])


def _rebuild_index(root: Path, subject: ProductSubject) -> RuntimeResolutionArtifactIndex:
    entries: list[RuntimeResolutionArtifactIndexEntry] = []
    identities: set[str] = set()
    contents: set[str] = set()
    for directory in (
        root / "runtime-resolution-parity",
        root / "reports" / "runtime-resolution-parity",
    ):
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
                schema = "omiv.runtime-resolution-markdown-report.v1"
                canonical_id = "runtime_markdown_" + digest[:32]
            if digest in contents or canonical_id in identities:
                raise ValueError("duplicate Phase 6E content or canonical identity at " + relative)
            contents.add(digest)
            identities.add(canonical_id)
            entries.append(
                RuntimeResolutionArtifactIndexEntry(
                    path=relative,
                    size=len(raw),
                    sha256=digest,
                    schema_id=schema,
                    canonical_id=canonical_id,
                )
            )
    return RuntimeResolutionArtifactIndex.model_validate(
        finalize_identity(
            {
                "schema": "omiv.runtime-resolution-artifact-index.v1",
                "subject": subject,
                "scope": "phase6e.generated.artifacts",
                "entries": sorted(entries, key=lambda item: item.path.encode()),
                "total_size": sum(item.size for item in entries),
                "limitations": ["External index excludes itself."],
            },
            "index_id",
            "runtime_index_",
            "index_digest",
        )
    )
