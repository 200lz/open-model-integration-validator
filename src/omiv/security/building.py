"""Deterministic builders for Phase 5F canonical records."""

from __future__ import annotations

from typing import Any, TypeVar

from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.security.models import (
    CoverageItem,
    CoverageStatus,
    CoverageSummary,
    FindingClassification,
    FindingConfidence,
    FindingEvidence,
    FindingExploitability,
    FindingLocation,
    FindingSeverity,
    FindingStatus,
    InspectionBounds,
    InspectionMethod,
    ScannerCapability,
    ScannerIdentity,
    SecurityFinding,
    SecurityInspectionPlan,
    SecurityInspectionScope,
)

T = TypeVar("T")


def identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    with_id = {**body, id_field: prefix + canonical_sha256(body)[:32]}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def artifact_reference(
    *,
    origin_type: str,
    variant: str,
    file_count: int,
    total_declared_bytes: int,
    content_digest: str | None = None,
    artifact_set_digest: str | None = None,
    format: str | None = None,
    provider: str | None = None,
    repository: str | None = None,
    repository_type: str | None = None,
    resolved_revision: str | None = None,
    selection: str | None = None,
) -> ArtifactReference:
    body = {
        "origin_type": origin_type,
        "provider": provider,
        "repository": repository,
        "repository_type": repository_type,
        "resolved_revision": resolved_revision,
        "selection": selection,
        "artifact_set_digest": artifact_set_digest,
        "content_digest": content_digest,
        "format": format,
        "architecture": None,
        "variant": variant,
        "file_count": file_count,
        "total_declared_bytes": total_declared_bytes,
        "passport_id": None,
        "passport_digest": None,
        "validation_inventory_digest": None,
    }
    identity = {
        k: v
        for k, v in body.items()
        if k not in {"passport_id", "passport_digest", "validation_inventory_digest"}
    }
    return ArtifactReference.model_validate({**body, "identity_digest": canonical_sha256(identity)})


def build_plan(
    subject: ArtifactReference,
    scope: SecurityInspectionScope,
    methods: list[InspectionMethod],
    bounds: InspectionBounds,
    *,
    limitations: list[str] | None = None,
) -> SecurityInspectionPlan:
    body = {
        "schema": "omiv.security-inspection-plan.v1",
        "subject": subject.model_dump(mode="json"),
        "scope": scope.model_dump(mode="json"),
        "methods": sorted({m.value for m in methods}),
        "bounds": bounds.model_dump(mode="json"),
        "follow_symlinks": False,
        "allow_decompression": False,
        "allow_code_execution": False,
        "allow_network_access": False,
        "limitations": sorted(
            limitations
            or [
                "Inspection is static and bounded; it does not establish runtime safety.",
            ]
        ),
    }
    return SecurityInspectionPlan.model_validate(
        identified(body, "plan_id", "inspection_plan_", "plan_digest")
    )


def builtin_scanner_identity() -> ScannerIdentity:
    methods = sorted(
        [
            InspectionMethod.METADATA_INSPECTION,
            InspectionMethod.FORMAT_STRUCTURE_INSPECTION,
            InspectionMethod.MANIFEST_INSPECTION,
            InspectionMethod.FILE_NAME_POLICY_CHECK,
            InspectionMethod.FILE_TYPE_POLICY_CHECK,
            InspectionMethod.MAGIC_BYTE_INSPECTION,
            InspectionMethod.ARCHIVE_STRUCTURE_INSPECTION,
            InspectionMethod.STATIC_PATTERN_INSPECTION,
            InspectionMethod.SERIALIZATION_FORMAT_INSPECTION,
            InspectionMethod.DEPENDENCY_MANIFEST_INSPECTION,
            InspectionMethod.SCRIPT_CONTENT_INSPECTION,
            InspectionMethod.EXECUTABLE_CONTENT_INSPECTION,
            InspectionMethod.BOUNDED_PAYLOAD_INSPECTION,
        ],
        key=lambda x: x.value,
    )
    categories = sorted(
        {
            FindingClassification.UNSAFE_SERIALIZATION_FORMAT,
            FindingClassification.SCRIPT_CONTENT_PRESENT,
            FindingClassification.NATIVE_BINARY_PRESENT,
            FindingClassification.PATH_TRAVERSAL_ENTRY,
            FindingClassification.SYMLINK_ENTRY,
            FindingClassification.PRIVATE_KEY_MATERIAL_PATTERN,
            FindingClassification.SIGNED_URL_PATTERN,
            FindingClassification.SUSPICIOUS_NETWORK_REFERENCE,
            FindingClassification.DYNAMIC_IMPORT_PATTERN,
            FindingClassification.SUBPROCESS_EXECUTION_PATTERN,
            FindingClassification.SHELL_EXECUTION_PATTERN,
            FindingClassification.DESERIALIZATION_EXECUTION_PATTERN,
            FindingClassification.INSTALL_OR_BUILD_SCRIPT_PRESENT,
            FindingClassification.DEPENDENCY_MANIFEST_PRESENT,
            FindingClassification.INCONSISTENT_MANIFEST,
        },
        key=lambda x: x.value,
    )
    capability = ScannerCapability(
        methods=methods,
        finding_categories=categories,
        payload_bytes_read=True,
        archive_metadata_only=True,
        code_execution=False,
        network_access=False,
        limitations=[
            "Pattern and format indicators are not semantic malware detection.",
            "Archive inspection reads bounded entry metadata only and never extracts content.",
        ],
    )
    implementation = {
        "name": "OMIV bounded static inspector",
        "revision": "phase-5f-v1",
        "methods": [m.value for m in methods],
        "categories": [c.value for c in categories],
    }
    body = {
        "schema": "omiv.scanner-identity.v1",
        "scanner_name": "OMIV bounded static inspector",
        "version": "1",
        "revision": "phase-5f-v1",
        "implementation_digest": canonical_sha256(implementation),
        "capability": capability.model_dump(mode="json"),
        "configuration_digest": canonical_sha256({"profile": "bounded-static-v1"}),
        "synthetic_builtin": True,
        "trust_references": [],
        "limitations": capability.limitations,
    }
    return ScannerIdentity.model_validate(
        identified(body, "scanner_id", "scanner_", "scanner_digest")
    )


def build_finding(
    *,
    category: FindingClassification,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    exploitability: FindingExploitability,
    subject_identity_digest: str,
    logical_path: str,
    indicator: str,
    evidence_digest: str,
    scanner_id: str,
    execution_id: str,
    byte_offset: int | None = None,
    byte_length: int | None = None,
    archive_entry: str | None = None,
    sensitive: bool = False,
    remediation: str = "Review the bounded indicator and apply an artifact-specific policy.",
    limitations: list[str] | None = None,
) -> SecurityFinding:
    evidence = FindingEvidence(
        role="normalized_indicator",
        evidence_digest=evidence_digest,
        indicator=indicator,
        redacted_fingerprint=evidence_digest if sensitive else None,
        sensitive_value_redacted=sensitive,
    )
    body = {
        "schema": "omiv.security-finding.v1",
        "category": category.value,
        "severity": severity.value,
        "confidence": confidence.value,
        "exploitability": exploitability.value,
        "status": FindingStatus.OPEN.value,
        "subject_identity_digest": subject_identity_digest,
        "location": FindingLocation(
            logical_path=logical_path,
            byte_offset=byte_offset,
            byte_length=byte_length,
            archive_entry=archive_entry,
        ).model_dump(mode="json"),
        "evidence": evidence.model_dump(mode="json"),
        "scanner_id": scanner_id,
        "scan_execution_id": execution_id,
        "applicable_policy_ids": [],
        "governance_evidence_ids": [],
        "limitations": sorted(
            limitations or ["Indicator does not by itself prove exploitability."]
        ),
        "remediation_guidance": remediation,
    }
    return SecurityFinding.model_validate(
        identified(body, "finding_id", "security_finding_", "finding_digest")
    )


def build_coverage(
    subject: ArtifactReference,
    items: list[CoverageItem],
    *,
    declared_files: int,
    declared_bytes: int,
    archive_entries_considered: int = 0,
    archive_entries_inspected: int = 0,
    limitations: list[str] | None = None,
) -> CoverageSummary:
    ordered = sorted(items, key=lambda x: x.logical_path)
    discovered = len(ordered)
    inspected = sum(x.status.value == "INSPECTED" for x in ordered)
    unsupported = sum(x.status.value == "UNSUPPORTED" for x in ordered)
    skipped = sum(x.status.value in {"SKIPPED", "NOT_CHECKED"} for x in ordered)
    errored = sum(x.status.value == "ERRORED" for x in ordered)
    discovered_bytes = sum(x.declared_bytes for x in ordered)
    inspected_bytes = sum(x.inspected_bytes for x in ordered)
    if errored:
        status = CoverageStatus.FAILED
    elif unsupported and not inspected:
        status = CoverageStatus.UNSUPPORTED
    elif (
        declared_files == discovered == inspected
        and declared_bytes == discovered_bytes == inspected_bytes
        and not unsupported
        and not skipped
    ):
        status = CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE
    elif inspected:
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.INCOMPLETE
    body = {
        "schema": "omiv.security-coverage.v1",
        "subject_identity_digest": subject.identity_digest,
        "items": [x.model_dump(mode="json") for x in ordered],
        "declared_files": declared_files,
        "discovered_files": discovered,
        "inspected_files": inspected,
        "unsupported_files": unsupported,
        "skipped_files": skipped,
        "errored_files": errored,
        "total_declared_bytes": declared_bytes,
        "total_discovered_bytes": discovered_bytes,
        "total_inspected_bytes": inspected_bytes,
        "bytes_not_inspected": discovered_bytes - inspected_bytes,
        "archive_entries_considered": archive_entries_considered,
        "archive_entries_inspected": archive_entries_inspected,
        "status": status.value,
        "limitations": sorted(limitations or []),
    }
    return CoverageSummary.model_validate(
        identified(body, "coverage_id", "security_coverage_", "coverage_digest")
    )
