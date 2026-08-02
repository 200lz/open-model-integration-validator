"""Bounded loading and deterministic Phase 5G JSON/Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.runtime.building import identified
from omiv.runtime.models import (
    ContinuityEvaluation,
    ContinuityPolicy,
    DeploymentManifest,
    DeploymentRecord,
    DeploymentRuntimeReport,
    ProductSubject,
    RuntimeObservation,
    RuntimeObservationPlan,
    RuntimeObserverIdentity,
)

MAX_RUNTIME_JSON_BYTES = 16 * 1024 * 1024
T = TypeVar("T")


def load_runtime(path: Path, model: type[T]) -> T:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("runtime input must be a regular non-symlink file")
    raw, _ = load_bounded_json(path, max_bytes=MAX_RUNTIME_JSON_BYTES)
    try:
        return model.model_validate(raw)  # type: ignore[attr-defined,no-any-return]
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime record: {exc}") from exc


def pretty_json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_runtime_report(
    subject: ProductSubject,
    manifest: DeploymentManifest,
    record: DeploymentRecord,
    observer: RuntimeObserverIdentity,
    observation: RuntimeObservation,
    evaluation: ContinuityEvaluation,
) -> DeploymentRuntimeReport:
    remediation: list[str] = []
    coverage = observation.coverage
    if coverage.unsupported_dimensions:
        remediation.append("Use an authorized observer with the required capability.")
    if coverage.inaccessible_dimensions:
        remediation.append("Provide bounded access to currently inaccessible dimensions.")
    if coverage.errored_dimensions:
        remediation.append("Resolve observer errors and capture new evidence.")
    if coverage.stale_dimensions:
        remediation.append("Capture a fresh observation under a new explicit context.")
    if coverage.proxy_only_dimensions:
        remediation.append("Capture direct identity evidence for proxy-only dimensions.")
    if evaluation.unobserved_dimensions:
        remediation.append("Observe every policy-required missing dimension.")
    body = {
        "schema": "omiv.deployment-runtime-report.v1",
        "subject_id": subject.subject_id,
        "artifact_set_id": manifest.artifact_set.artifact_set_id,
        "scope": subject.scope.model_dump(mode="json"),
        "intent_id": manifest.intent_id,
        "instance_id": manifest.instance.instance_id,
        "manifest_id": manifest.manifest_id,
        "deployment_record_id": record.record_id,
        "deployment_status": record.status.value,
        "deployment_evidence_origin": record.assertion.origin.value,
        "target_id": manifest.target.target_id,
        "engine_id": manifest.engine.engine_id,
        "environment_id": manifest.expected_environment.environment_id,
        "observer_id": observer.observer_id,
        "observation_id": observation.observation_id,
        "observation_strength": observation.assertion.origin.value,
        "source_security_verdict": manifest.security_verdict,
        "source_security_limitations": manifest.security_limitations,
        "coverage": observation.coverage.model_dump(mode="json", by_alias=True),
        "coverage_remediation": remediation,
        "evaluation": evaluation.model_dump(mode="json", by_alias=True),
        "deployment_performed_by_omiv": False,
        "limitations": sorted(
            {*evaluation.limitations, "OMIV performed no external deployment action."}
        ),
    }
    return DeploymentRuntimeReport.model_validate(
        identified(body, "report_id", "runtime_report_", "report_digest")
    )


def verify_runtime_report(
    observed: DeploymentRuntimeReport,
    subject: ProductSubject,
    manifest: DeploymentManifest,
    record: DeploymentRecord,
    observer: RuntimeObserverIdentity,
    observation: RuntimeObservation,
    evaluation: ContinuityEvaluation,
) -> DeploymentRuntimeReport:
    expected = build_runtime_report(subject, manifest, record, observer, observation, evaluation)
    if expected != observed:
        raise OmivInputError("runtime report does not match deterministic reconstruction")
    return observed


def render_runtime_markdown(report: DeploymentRuntimeReport) -> str:
    evaluation = report.evaluation
    runtime_observed = "YES" if evaluation.observation_integrity == "VALID" else "NO"
    coverage_fraction = (
        f"{len(report.coverage.observed_dimensions)}/{len(report.coverage.expected_dimensions)}"
    )
    proxy = ", ".join(x.value for x in report.coverage.proxy_only_dimensions) or "None"
    missing = ", ".join(x.value for x in evaluation.unobserved_dimensions) or "None"
    limitations = [f"- {x}" for x in report.limitations]
    remediation = [f"- {x}" for x in report.coverage_remediation] or ["- None"]
    return "\n".join(
        [
            "# OMIV Deployment and Runtime Snapshot Report",
            "",
            "- Deployment performed by OMIV: **NO**",
            f"- Deployment evidence origin: **{report.deployment_evidence_origin.value}**",
            f"- Runtime observed: **{runtime_observed}**",
            f"- Observation strength: **{report.observation_strength.value}**",
            f"- Source security verdict: **{report.source_security_verdict}**",
            f"- Required dimensions observed: **{coverage_fraction}**",
            f"- Proxy-only dimensions: `{proxy}`",
            f"- Unobserved dimensions: `{missing}`",
            f"- Approved artifact set: `{report.artifact_set_id}`",
            f"- Artifact-set continuity: **{evaluation.artifact_set_continuity.value}**",
            f"- Configuration continuity: **{evaluation.configuration_continuity.value}**",
            f"- Engine binary continuity: **{evaluation.engine_continuity.value}**",
            f"- Observer authority: **{evaluation.observer_authority.value}**",
            f"- Replay status: **{evaluation.replay_status}**",
            f"- Observation freshness: **{evaluation.freshness.value}**",
            f"- Trusted timestamp: **{evaluation.trusted_timestamp_status}**",
            f"- Revocation status: **{evaluation.revocation_status}**",
            f"- Trust-bundle freshness: **{evaluation.trust_bundle_freshness}**",
            f"- Policy-scoped verdict: **{evaluation.verdict.value}**",
            "- Snapshot only: **YES**",
            "- Behavioral parity: **NOT_CHECKED**",
            "- Runtime safety: **NOT_VERIFIED**",
            "- Continuous continuity: **NOT_ESTABLISHED**",
            "",
            "## Limitations",
            "",
            *limitations,
            "",
            "## Coverage remediation",
            "",
            *remediation,
            "",
            "> A continuity PASS is scoped to the selected policy, supplied evidence, observed",
            "> dimensions, deployment instance, scope, trust domain, and evaluation context.",
            "> Snapshot continuity does not establish behavior, numerical parity, safety, or",
            "> continuously unchanged state.",
            "",
        ]
    )


LOADABLE_MODELS: dict[str, type[BaseModel]] = {
    "omiv.product-subject.v1": ProductSubject,
    "omiv.deployment-manifest.v1": DeploymentManifest,
    "omiv.deployment-record.v1": DeploymentRecord,
    "omiv.runtime-observer-identity.v1": RuntimeObserverIdentity,
    "omiv.runtime-observation-plan.v1": RuntimeObservationPlan,
    "omiv.runtime-observation.v1": RuntimeObservation,
    "omiv.continuity-policy.v1": ContinuityPolicy,
    "omiv.continuity-evaluation.v1": ContinuityEvaluation,
    "omiv.deployment-runtime-report.v1": DeploymentRuntimeReport,
}
