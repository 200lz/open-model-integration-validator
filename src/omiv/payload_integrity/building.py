"""Deterministic Phase 6A builders and factual comparison."""

from __future__ import annotations

from typing import Any

from pydantic import TypeAdapter

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.payload_integrity.models import (
    ComparisonStatus,
    CompletionState,
    EvidenceOutcome,
    ExpectationMode,
    ExpectationScope,
    ExplicitTime,
    FindingKind,
    IntegrationLink,
    MaterializationState,
    ObservedPayloadManifest,
    PathFinding,
    PayloadExpectation,
    PayloadExpectationMaterialization,
    PayloadFileRecord,
    PayloadIntegrityEvidence,
    PayloadIntegrityPolicy,
    PayloadIntegrityReport,
    PayloadInventoryPlan,
    PayloadManifestComparison,
    PayloadPublisherAuthorityEvaluation,
    ResourceLimits,
    RootMode,
)
from omiv.payload_integrity.paths import validate_path_set
from omiv.runtime.models import ProductSubject
from omiv.trust.models import OverallSignedObjectStatus, SignatureReport


def identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    identity = prefix + canonical_sha256(body)[:32]
    with_id = {**body, id_field: identity}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def digested(body: dict[str, Any], digest_field: str) -> dict[str, Any]:
    return {**body, digest_field: canonical_sha256(body)}


def artifact_set_digest(
    root_mode: RootMode, logical_root: str, records: tuple[PayloadFileRecord, ...]
) -> str:
    ordered = sorted(records, key=lambda x: x.path.encode("utf-8"))
    validate_path_set(tuple(x.path for x in ordered))
    return canonical_sha256(
        {
            "domain": "omiv.payload-artifact-set.v1",
            "root_mode": root_mode.value,
            "logical_root": logical_root,
            "files": [
                {
                    "path": x.path,
                    "size": x.size,
                    "primary_content_digest": x.primary_content_digest.model_dump(mode="json"),
                    "artifact_role": x.artifact_role.value,
                    "declared_role_detail": x.declared_role_detail,
                }
                for x in ordered
            ],
        }
    )


def build_plan(
    subject: ProductSubject,
    root_mode: RootMode,
    logical_root: str,
    *,
    logical_name: str | None = None,
    chunk_size: int = 1024 * 1024,
    declared_context: str = "context.not-recorded",
) -> PayloadInventoryPlan:
    body = {
        "schema": "omiv.payload-inventory-plan.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "root_mode": root_mode.value,
        "logical_root": logical_root,
        "single_file_logical_name": logical_name,
        "traversal_policy": "ITERATIVE_NO_FOLLOW",
        "hardlink_policy": "REJECT_HARDLINK_ALIASES",
        "symlink_policy": "REJECT",
        "special_file_policy": "REJECT",
        "path_normalization_policy": "OMIV_PORTABLE_NFC_V1",
        "primary_digest_algorithm": "SHA256",
        "chunk_size": chunk_size,
        "limits": ResourceLimits().model_dump(mode="json"),
        "exclusions": [],
        "requested_coverage": "ALL_REGULAR_FILES_IN_DECLARED_LOCAL_SCOPE",
        "declared_context": declared_context,
        "limitations": ["Plan is a declaration and does not prove observation or execution."],
    }
    return PayloadInventoryPlan.model_validate(
        identified(body, "plan_id", "payload_plan_", "plan_digest")
    )


def build_expectation(
    subject: ProductSubject,
    root_mode: RootMode,
    logical_root: str,
    records: tuple[PayloadFileRecord, ...],
    scope: ExpectationScope,
    *,
    source_provider: str = "provider.declared",
    source_namespace: str = "namespace.declared",
    available_at: str = "NOT_RECORDED",
) -> PayloadExpectation:
    ordered = tuple(sorted(records, key=lambda x: x.path.encode()))
    body = {
        "schema": "omiv.payload-expectation.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "root_mode": root_mode.value,
        "logical_root": logical_root,
        "representation_mode": "EMBEDDED_EXPECTATION",
        "materialization_state": "FULL_EXPECTATION_AVAILABLE",
        "expectation_scope": scope.value,
        "expected_records": [x.model_dump(mode="json") for x in ordered],
        "expected_artifact_set_digest": artifact_set_digest(root_mode, logical_root, ordered),
        "referenced_schema_id": None,
        "referenced_object_id": None,
        "referenced_object_digest": None,
        "declaration_provenance": "DECLARED",
        "declared_purpose": "payload.byte-identity",
        "authority_status": "NOT_EVALUATED",
        "source_provider": source_provider,
        "source_namespace": source_namespace,
        "available_at": available_at,
        "limitations": [
            "Expected bytes are declared; correctness and publisher authority are separate."
        ],
    }
    return PayloadExpectation.model_validate(
        identified(body, "expectation_id", "payload_expectation_", "expectation_digest")
    )


def build_reference(
    expectation: PayloadExpectation,
    *,
    state: MaterializationState = MaterializationState.DIGEST_REFERENCE_ONLY,
    available_at: str = "NOT_RECORDED",
) -> PayloadExpectation:
    if state == MaterializationState.FULL_EXPECTATION_AVAILABLE:
        raise OmivInputError("full availability requires a separate materialization result")
    body = {
        "schema": "omiv.payload-expectation.v1",
        "subject": expectation.subject.model_dump(mode="json", by_alias=True),
        "root_mode": expectation.root_mode.value,
        "logical_root": expectation.logical_root,
        "representation_mode": "REFERENCED_EXPECTATION",
        "materialization_state": state.value,
        "expectation_scope": expectation.expectation_scope.value,
        "expected_records": [],
        "expected_artifact_set_digest": expectation.expected_artifact_set_digest,
        "referenced_schema_id": expectation.schema_id,
        "referenced_object_id": expectation.expectation_id,
        "referenced_object_digest": expectation.expectation_digest,
        "declaration_provenance": "DECLARED",
        "declared_purpose": "payload.byte-identity",
        "authority_status": "NOT_EVALUATED",
        "source_provider": expectation.source_provider,
        "source_namespace": expectation.source_namespace,
        "available_at": available_at,
        "limitations": [
            "Referenced expectation is usable only when the exact canonical object is supplied."
        ],
    }
    return PayloadExpectation.model_validate(
        identified(body, "expectation_id", "payload_expectation_", "expectation_digest")
    )


def build_publisher_authority_evaluation(
    expectation: PayloadExpectation,
    *,
    trust_report: SignatureReport,
    authorized: bool,
    evaluated_at: str = "NOT_RECORDED",
) -> PayloadPublisherAuthorityEvaluation:
    if (
        trust_report.signed_object_id != expectation.expectation_id
        or trust_report.signed_object_digest
        != canonical_sha256(expectation.model_dump(mode="json", by_alias=True))
        or not trust_report.signature_results
    ):
        raise OmivInputError("trust report does not bind the exact expectation")
    trusted = (
        trust_report.overall_status == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
    )
    if authorized and not trusted:
        raise OmivInputError("publisher authorization requires a trusted exact-object signature")
    signature = trust_report.signature_results[0]
    body = {
        "schema": "omiv.payload-publisher-authority-evaluation.v1",
        "expectation_id": expectation.expectation_id,
        "expectation_digest": expectation.expectation_digest,
        "subject_id": expectation.subject.subject_id,
        "source_provider": expectation.source_provider,
        "source_namespace": expectation.source_namespace,
        "purpose": expectation.declared_purpose,
        "scope": expectation.subject.scope.model_dump(mode="json"),
        "expectation_scope": expectation.expectation_scope.value,
        "trust_report_id": trust_report.report_id,
        "trust_report_digest": trust_report.report_digest,
        "signer_id": signature.signer_identity_id or "signer.identity-unavailable",
        "key_id": signature.key_id,
        "signer_binding_status": signature.signer_binding_status.value
        if signature.signer_binding_status
        else "NOT_EVALUATED",
        "signature_trust": "TRUSTED" if trusted else "UNTRUSTED",
        "authority_status": "AUTHORIZED_PUBLISHER" if authorized else "UNAUTHORIZED",
        "evaluated_at": evaluated_at,
        "limitations": [
            "Authority is scoped to this exact expectation and does not prove it correct."
        ],
    }
    return PayloadPublisherAuthorityEvaluation.model_validate(
        identified(
            body,
            "authority_evaluation_id",
            "payload_authority_",
            "authority_evaluation_digest",
        )
    )


def materialize_reference(
    reference: PayloadExpectation,
    supplied: PayloadExpectation,
    *,
    evaluated_at: str = "NOT_RECORDED",
) -> PayloadExpectationMaterialization:
    if reference.representation_mode != ExpectationMode.REFERENCED_EXPECTATION:
        raise OmivInputError("materialization requires a referenced expectation declaration")
    if (
        supplied.representation_mode != ExpectationMode.EMBEDDED_EXPECTATION
        or supplied.materialization_state != MaterializationState.FULL_EXPECTATION_AVAILABLE
    ):
        raise OmivInputError("supplied object must be a fully available canonical expectation")
    if (
        reference.referenced_schema_id != supplied.schema_id
        or reference.referenced_object_id != supplied.expectation_id
        or reference.referenced_object_digest != supplied.expectation_digest
        or reference.subject != supplied.subject
        or reference.root_mode != supplied.root_mode
        or reference.logical_root != supplied.logical_root
        or reference.expectation_scope != supplied.expectation_scope
    ):
        raise OmivInputError("referenced expectation canonical identity or scope mismatch")
    body = {
        "schema": "omiv.payload-expectation-materialization.v1",
        "reference_expectation_id": reference.expectation_id,
        "reference_expectation_digest": reference.expectation_digest,
        "supplied_schema_id": supplied.schema_id,
        "supplied_expectation_id": supplied.expectation_id,
        "supplied_expectation_digest": supplied.expectation_digest,
        "materialization_state": MaterializationState.FULL_EXPECTATION_AVAILABLE.value,
        "reference_available_at": reference.available_at,
        "supplied_available_at": supplied.available_at,
        "evaluated_at": evaluated_at,
        "authority_transfer": "NOT_PERFORMED",
        "limitations": [
            "Materialization verifies exact reference binding; authority and availability "
            "do not transfer."
        ],
    }
    return PayloadExpectationMaterialization.model_validate(
        identified(
            body,
            "materialization_id",
            "payload_materialization_",
            "materialization_digest",
        )
    )


def materialization_known_as_of_cutoff(
    materialization: PayloadExpectationMaterialization, cutoff: str
) -> bool:
    """Return whether both immutable inputs were supplied by an explicit cutoff."""
    canonical_cutoff = TypeAdapter(ExplicitTime).validate_python(cutoff)
    if canonical_cutoff == "NOT_RECORDED":
        return False
    return all(
        value != "NOT_RECORDED" and value <= canonical_cutoff
        for value in (
            materialization.reference_available_at,
            materialization.supplied_available_at,
        )
    )


def compare_manifests(
    expectation: PayloadExpectation,
    observed: ObservedPayloadManifest,
    *,
    reference: PayloadExpectation | None = None,
    materialization: PayloadExpectationMaterialization | None = None,
) -> PayloadManifestComparison:
    if (reference is None) != (materialization is None):
        raise OmivInputError("comparison requires both reference and materialization")
    if (
        reference is not None
        and materialization is not None
        and (
            materialization.reference_expectation_id != reference.expectation_id
            or materialization.reference_expectation_digest != reference.expectation_digest
            or materialization.supplied_expectation_id != expectation.expectation_id
            or materialization.supplied_expectation_digest != expectation.expectation_digest
        )
    ):
        raise OmivInputError("materialization does not bind comparison inputs")
    compatible = (
        expectation.subject == observed.subject,
        expectation.root_mode == observed.root_mode,
        expectation.logical_root == observed.logical_root,
    )
    findings: list[PathFinding] = []
    matching: list[str] = []
    missing: list[str] = []
    extra: list[str] = []
    outside: list[str] = []
    if expectation.materialization_state == MaterializationState.DIGEST_REFERENCE_ONLY:
        status = ComparisonStatus.DIGEST_REFERENCE_ONLY
    elif expectation.materialization_state == MaterializationState.EXPECTATION_UNAVAILABLE:
        status = ComparisonStatus.EXPECTATION_UNAVAILABLE
    elif expectation.materialization_state == MaterializationState.EXPECTATION_INVALID:
        status = ComparisonStatus.INVALID_EXPECTATION
    elif not all(compatible):
        status = ComparisonStatus.INCOMPATIBLE_SCOPE
    elif observed.completion_state == CompletionState.LIMIT_EXCEEDED:
        status = ComparisonStatus.LIMIT_EXCEEDED
    elif observed.completion_state != CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE:
        status = ComparisonStatus.INCOMPLETE_OBSERVATION
    else:
        expected = {x.path: x for x in expectation.expected_records}
        actual = {x.path: x for x in observed.files}
        for path in sorted(expected.keys() | actual.keys(), key=lambda x: x.encode()):
            e = expected.get(path)
            a = actual.get(path)
            kinds: list[FindingKind] = []
            if e is None and a is not None:
                if expectation.expectation_scope == ExpectationScope.COMPLETE_DECLARED_FILE_SET:
                    kinds.append(FindingKind.PATH_EXTRA)
                    extra.append(path)
                else:
                    kinds.append(FindingKind.PATH_OUTSIDE_EXPECTATION_SCOPE)
                    outside.append(path)
            elif e is not None and a is None:
                kinds.append(FindingKind.PATH_MISSING)
                missing.append(path)
            elif e is not None and a is not None:
                kinds.append(FindingKind.PATH_MATCH)
                kinds.append(
                    FindingKind.SIZE_MATCH if e.size == a.size else FindingKind.SIZE_MISMATCH
                )
                kinds.append(
                    FindingKind.CONTENT_DIGEST_MATCH
                    if e.primary_content_digest == a.primary_content_digest
                    else FindingKind.CONTENT_DIGEST_MISMATCH
                )
                kinds.append(
                    FindingKind.ROLE_MATCH
                    if (e.artifact_role, e.declared_role_detail)
                    == (a.artifact_role, a.declared_role_detail)
                    else FindingKind.ROLE_MISMATCH
                )
                kinds.append(
                    FindingKind.TYPE_MATCH
                    if e.logical_file_kind == a.logical_file_kind
                    else FindingKind.TYPE_MISMATCH
                )
                if all(
                    x in kinds
                    for x in (
                        FindingKind.SIZE_MATCH,
                        FindingKind.CONTENT_DIGEST_MATCH,
                        FindingKind.ROLE_MATCH,
                        FindingKind.TYPE_MATCH,
                    )
                ):
                    matching.append(path)
            findings.append(
                PathFinding(
                    path=path,
                    findings=tuple(kinds),
                    expected_size=e.size if e else None,
                    observed_size=a.size if a else None,
                    expected_digest=e.primary_content_digest.value if e else None,
                    observed_digest=a.primary_content_digest.value if a else None,
                )
            )
        bad = {
            FindingKind.PATH_MISSING,
            FindingKind.PATH_EXTRA,
            FindingKind.SIZE_MISMATCH,
            FindingKind.CONTENT_DIGEST_MISMATCH,
            FindingKind.ROLE_MISMATCH,
            FindingKind.TYPE_MISMATCH,
        }
        status = (
            ComparisonStatus.MISMATCH
            if any(set(x.findings) & bad for x in findings)
            else ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
        )
    body = {
        "schema": "omiv.payload-manifest-comparison.v1",
        "expectation_id": expectation.expectation_id,
        "expectation_digest": expectation.expectation_digest,
        "reference_expectation_id": reference.expectation_id if reference else None,
        "reference_expectation_digest": reference.expectation_digest if reference else None,
        "supplied_expectation_id": expectation.expectation_id if reference else None,
        "supplied_expectation_digest": expectation.expectation_digest if reference else None,
        "materialization_id": materialization.materialization_id if materialization else None,
        "materialization_digest": materialization.materialization_digest
        if materialization
        else None,
        "representation_mode": (
            ExpectationMode.REFERENCED_EXPECTATION.value
            if reference
            else expectation.representation_mode.value
        ),
        "materialization_state": (
            materialization.materialization_state
            if materialization
            else expectation.materialization_state.value
        ),
        "expectation_scope": expectation.expectation_scope.value,
        "observed_manifest_id": observed.manifest_id,
        "observed_manifest_digest": observed.manifest_digest,
        "subject_compatible": compatible[0],
        "root_mode_compatible": compatible[1],
        "logical_scope_compatible": compatible[2],
        "findings": [x.model_dump(mode="json") for x in findings],
        "matching_required_members": matching,
        "missing_members": missing,
        "extra_members": extra,
        "outside_scope_members": outside,
        "status": status.value,
        "limitations": [
            "Comparison is factual only for the declared expectation scope; matching bytes "
            "do not prove semantics or authenticity."
        ],
    }
    return PayloadManifestComparison.model_validate(
        identified(body, "comparison_id", "payload_comparison_", "comparison_digest")
    )


def evaluate_evidence(
    observed: ObservedPayloadManifest,
    execution_id: str,
    comparison: PayloadManifestComparison | None = None,
    expectation: PayloadExpectation | None = None,
    policy: PayloadIntegrityPolicy | None = None,
    authority_evaluation: PayloadPublisherAuthorityEvaluation | None = None,
    *,
    evaluated_at: str = "NOT_RECORDED",
) -> PayloadIntegrityEvidence:
    if execution_id != observed.execution_id:
        raise OmivInputError("execution reference does not match observed manifest")
    if comparison is not None and (
        comparison.observed_manifest_id != observed.manifest_id
        or comparison.observed_manifest_digest != observed.manifest_digest
    ):
        raise OmivInputError("comparison does not bind the supplied observed manifest")
    if (
        comparison is not None
        and expectation is not None
        and (
            comparison.expectation_id != expectation.expectation_id
            or comparison.expectation_digest != expectation.expectation_digest
        )
    ):
        raise OmivInputError("comparison does not bind the supplied expectation")
    if authority_evaluation is not None and (
        expectation is None
        or authority_evaluation.expectation_id != expectation.expectation_id
        or authority_evaluation.expectation_digest != expectation.expectation_digest
        or authority_evaluation.subject_id != expectation.subject.subject_id
        or authority_evaluation.source_provider != expectation.source_provider
        or authority_evaluation.source_namespace != expectation.source_namespace
        or authority_evaluation.purpose != expectation.declared_purpose
        or authority_evaluation.scope != expectation.subject.scope
        or authority_evaluation.expectation_scope != expectation.expectation_scope
    ):
        raise OmivInputError("publisher authority evaluation scope mismatch")
    publisher_authorized = (
        authority_evaluation is not None
        and authority_evaluation.signature_trust == "TRUSTED"
        and authority_evaluation.authority_status == "AUTHORIZED_PUBLISHER"
    )
    if comparison is None:
        outcome = EvidenceOutcome.OBSERVED
    elif comparison.status == ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE:
        if (
            expectation
            and expectation.expectation_scope == ExpectationScope.COMPLETE_DECLARED_FILE_SET
        ):
            outcome = (
                EvidenceOutcome.MATCHES_AUTHORIZED_COMPLETE_EXPECTATION
                if publisher_authorized
                else EvidenceOutcome.MATCHES_COMPLETE_EXPECTATION
            )
        else:
            outcome = EvidenceOutcome.MATCHES_EXPECTATION_SCOPE
    elif comparison.status == ComparisonStatus.MISMATCH:
        outcome = EvidenceOutcome.MISMATCH
    elif comparison.status == ComparisonStatus.DIGEST_REFERENCE_ONLY:
        outcome = EvidenceOutcome.DIGEST_REFERENCE_ONLY
    elif comparison.status == ComparisonStatus.EXPECTATION_UNAVAILABLE:
        outcome = EvidenceOutcome.EXPECTATION_UNAVAILABLE
    elif comparison.status == ComparisonStatus.LIMIT_EXCEEDED:
        outcome = EvidenceOutcome.LIMIT_EXCEEDED
    elif comparison.status == ComparisonStatus.INCOMPLETE_OBSERVATION:
        outcome = EvidenceOutcome.INCOMPLETE
    else:
        outcome = EvidenceOutcome.NOT_COMPARABLE
    policy_satisfied: bool | None = None
    if policy:
        policy_satisfied = (
            policy.scope == observed.subject.scope
            and observed.completion_state in policy.accepted_completion_states
            and comparison is not None
            and comparison.status == ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
            and expectation is not None
            and expectation.expectation_scope == policy.required_expectation_scope
            and (not policy.require_authorized_publisher or publisher_authorized)
            and (policy.allow_extra_files or not comparison.extra_members)
            and (policy.allow_outside_scope or not comparison.outside_scope_members)
            and (policy.allow_exclusions or not observed.coverage.excluded_paths)
        )
        if policy.scope != observed.subject.scope:
            outcome = EvidenceOutcome.INVALID
    body = {
        "schema": "omiv.payload-integrity-evidence.v1",
        "subject_id": observed.subject.subject_id,
        "subject_scope_digest": canonical_sha256(observed.subject.scope.model_dump(mode="json")),
        "root_mode": observed.root_mode.value,
        "logical_root": observed.logical_root,
        "plan_id": observed.plan_id,
        "plan_digest": observed.plan_digest,
        "manifest_id": observed.manifest_id,
        "manifest_digest": observed.manifest_digest,
        "execution_id": execution_id,
        "execution_digest": observed.execution_digest,
        "expectation_id": expectation.expectation_id if expectation else None,
        "expectation_digest": expectation.expectation_digest if expectation else None,
        "expectation_scope": expectation.expectation_scope.value if expectation else None,
        "materialization_state": expectation.materialization_state.value if expectation else None,
        "comparison_id": comparison.comparison_id if comparison else None,
        "comparison_digest": comparison.comparison_digest if comparison else None,
        "policy_id": policy.policy_id if policy else None,
        "policy_digest": policy.policy_digest if policy else None,
        "artifact_set_payload_digest": observed.artifact_set_payload_digest,
        "comparison_status": comparison.status.value if comparison else None,
        "policy_satisfied": policy_satisfied,
        "publisher_authority_status": (
            authority_evaluation.authority_status if authority_evaluation else "NOT_EVALUATED"
        ),
        "authority_evaluation_id": (
            authority_evaluation.authority_evaluation_id if authority_evaluation else None
        ),
        "authority_evaluation_digest": (
            authority_evaluation.authority_evaluation_digest if authority_evaluation else None
        ),
        "coverage": observed.coverage.model_dump(mode="json"),
        "available_at": observed.available_at,
        "observed_at": observed.observed_at,
        "evaluated_at": evaluated_at,
        "provenance_strength": "SYSTEM_OBSERVED",
        "outcome": outcome.value,
        "limitations": [
            "Payload byte identity does not establish provenance, semantic correctness, safety, "
            "approval, deployment, or runtime identity."
        ],
    }
    return PayloadIntegrityEvidence.model_validate(
        identified(body, "evidence_id", "payload_evidence_", "evidence_digest")
    )


def build_policy(
    policy_id: str,
    scope: object,
    *,
    expectation_scope: ExpectationScope,
    require_authorized_publisher: bool,
) -> PayloadIntegrityPolicy:
    from omiv.runtime.models import ScopeContext

    if not isinstance(scope, ScopeContext):
        raise OmivInputError("payload policy requires a canonical scope")
    body = {
        "schema": "omiv.payload-integrity-policy.v1",
        "policy_id": policy_id,
        "scope": scope.model_dump(mode="json"),
        "accepted_algorithms": ["SHA256"],
        "required_expectation_scope": expectation_scope.value,
        "require_authorized_publisher": require_authorized_publisher,
        "allow_extra_files": False,
        "allow_outside_scope": expectation_scope != ExpectationScope.COMPLETE_DECLARED_FILE_SET,
        "allow_exclusions": False,
        "accepted_completion_states": ["COMPLETE_FOR_DECLARED_LOCAL_SCOPE"],
        "limitations": [
            "Policy satisfaction does not prove expectation correctness or artifact safety."
        ],
    }
    return PayloadIntegrityPolicy.model_validate(digested(body, "policy_digest"))


def build_integration(
    kind: str,
    evidence: PayloadIntegrityEvidence,
    *,
    accepted: bool,
    source_status: str,
    source_object_id: str | None = None,
    source_object_digest: str | None = None,
    source_scope_digest: str | None = None,
    coverage_status: str | None = None,
    source_limitations: tuple[str, ...] = (),
    expected_runtime_payload_digest: str | None = None,
    runtime_boundary: bool = False,
    temporal: bool = False,
) -> IntegrationLink:
    body = {
        "schema": "omiv.payload-integrity-integration.v1",
        "integration_type": kind,
        "subject_id": evidence.subject_id,
        "payload_evidence_id": evidence.evidence_id,
        "payload_evidence_digest": evidence.evidence_digest,
        "payload_digest": evidence.artifact_set_payload_digest,
        "accepted": accepted,
        "source_status": source_status,
        "source_object_id": source_object_id,
        "source_object_digest": source_object_digest,
        "source_scope_digest": source_scope_digest,
        "coverage_status": coverage_status,
        "source_limitations": list(source_limitations),
        "expected_runtime_payload_digest": expected_runtime_payload_digest,
        "observed_runtime_payload_digest": None,
        "runtime_observer_assertion": "NOT_CREATED" if runtime_boundary else None,
        "deployment_status": "NOT_PERFORMED" if runtime_boundary else None,
        "runtime_continuity": "NOT_EVALUATED" if runtime_boundary else None,
        "behavioral_correctness": "NOT_EVALUATED" if runtime_boundary else None,
        "available_at": evidence.available_at if temporal else None,
        "observed_at": evidence.observed_at if temporal else None,
        "evaluated_at": evidence.evaluated_at if temporal else None,
        "known_as_of_cutoff_eligible": (
            evidence.available_at != "NOT_RECORDED" if temporal else None
        ),
        "limitations": ["Adapter preserves source scope and cannot upgrade payload evidence."],
    }
    return IntegrationLink.model_validate(
        identified(body, "integration_id", "payload_integration_", "integration_digest")
    )


def build_report(
    evidence: PayloadIntegrityEvidence, comparison: PayloadManifestComparison | None
) -> PayloadIntegrityReport:
    body = {
        "schema": "omiv.payload-integrity-report.v1",
        "evidence": evidence.model_dump(mode="json", by_alias=True),
        "comparison": comparison.model_dump(mode="json", by_alias=True) if comparison else None,
        "local_payload_bytes_match": comparison is not None
        and comparison.status == ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE,
        "model_semantic_correctness": "NOT_EVALUATED",
        "remote_repository_completeness": "NOT_EVALUATED",
        "runtime_safety": "NOT_VERIFIED",
        "continuous_verification": "NOT_ESTABLISHED",
        "limitations": ["Report is derived output, not an evidence source."],
    }
    return PayloadIntegrityReport.model_validate(
        identified(body, "report_id", "payload_report_", "report_digest")
    )
