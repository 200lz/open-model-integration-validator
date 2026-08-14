"""Offline preflight, assembly, and verification for Assurance Bundles."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from omiv.assurance.models import (
    AssuranceBundleManifest,
    AssuranceDimension,
    AssurancePlan,
    AssuranceRequest,
    AssuranceSubjectDocument,
    AssuranceVerdictDocument,
    AssuranceVerificationReport,
    Availability,
    BundleMember,
    BundleStatus,
    CapabilitiesDocument,
    CoreFileRecord,
    CostClass,
    CostSummary,
    DimensionVerdict,
    EvidenceIndexDocument,
    EvidencePhase,
    FindingRecord,
    FindingsDocument,
    PreflightMember,
    PreflightStatus,
    SchemaSupport,
    UnknownRecord,
    UnknownsDocument,
    VerdictRole,
    VerdictStatus,
    VerificationFinding,
)
from omiv.assurance.projection import project_semantic_status
from omiv.assurance.registry import schema_model, supported_schemas
from omiv.canonical import canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.safe_write import atomic_write_text

MAX_CONTROL_BYTES = 8 * 1024 * 1024
MAX_JSON_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MANIFEST_NAME = "assurance-bundle.json"
CORE_FILES = (
    "subject.json",
    "verdict.json",
    "evidence-index.json",
    "findings.json",
    "unknowns.json",
    "capabilities.json",
)
FEATURES = (
    "concise-verdict",
    "explicit-unknowns",
    "phase5-through-6e-schema-validation",
    "portable-directory",
    "deterministic-zip-stored",
    "detached-ed25519-signatures",
    "offline-verification",
)
CORE_MODELS: dict[str, type[BaseModel]] = {
    "omiv.assurance-subject.v1": AssuranceSubjectDocument,
    "omiv.assurance-verdict.v1": AssuranceVerdictDocument,
    "omiv.assurance-evidence-index.v1": EvidenceIndexDocument,
    "omiv.assurance-findings.v1": FindingsDocument,
    "omiv.assurance-unknowns.v1": UnknownsDocument,
    "omiv.assurance-capabilities.v1": CapabilitiesDocument,
}


def _pretty(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def load_request(path: Path) -> AssuranceRequest:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return AssuranceRequest.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Assurance Bundle request: {exc}") from exc


def load_plan(path: Path) -> AssurancePlan:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return AssurancePlan.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Assurance Plan: {exc}") from exc


def load_manifest(path: Path) -> AssuranceBundleManifest:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return AssuranceBundleManifest.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Assurance Bundle manifest: {exc}") from exc


def _safe_source(root: Path, portable_path: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / Path(*portable_path.split("/"))).resolve(strict=False)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise OmivInputError("evidence source escapes the declared root")
    return candidate


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _schema_status(
    raw: bytes, phase: EvidencePhase, expected: str | None
) -> tuple[SchemaSupport, list[str], dict[str, Any] | None]:
    if expected is None:
        return SchemaSupport.NOT_DECLARED, ["EVIDENCE_SCHEMA_NOT_DECLARED"], None
    model = schema_model(phase, expected)
    if model is None:
        return SchemaSupport.UNSUPPORTED, ["EVIDENCE_SCHEMA_UNSUPPORTED_FOR_PHASE"], None
    try:
        value = load_json_value(raw.decode("utf-8"))
    except (UnicodeError, OmivInputError):
        return SchemaSupport.MISMATCH, ["EVIDENCE_JSON_INVALID"], None
    if not isinstance(value, dict) or value.get("schema") != expected:
        return SchemaSupport.MISMATCH, ["EVIDENCE_SCHEMA_MISMATCH"], None
    try:
        model.model_validate(value)
    except (ValidationError, ValueError):
        return SchemaSupport.MISMATCH, ["EVIDENCE_SCHEMA_VALIDATION_FAILED"], value
    return SchemaSupport.SUPPORTED_AND_VALID, [], value


def _inspect_member(root: Path, requirement: Any) -> PreflightMember:
    source = _safe_source(root, requirement.source_path)
    issues: list[str] = []
    if not source.exists():
        return PreflightMember(
            **requirement.model_dump(mode="json"),
            availability=Availability.MISSING,
            schema_support=(
                SchemaSupport.NOT_APPLICABLE
                if requirement.media_type != "application/json"
                else SchemaSupport.NOT_DECLARED
            ),
            issues=[
                "REQUIRED_EVIDENCE_MISSING" if requirement.required else "OPTIONAL_EVIDENCE_MISSING"
            ],
        )
    if source.is_symlink() or not source.is_file():
        return PreflightMember(
            **requirement.model_dump(mode="json"),
            availability=Availability.INVALID_LOCAL_OBJECT,
            schema_support=(
                SchemaSupport.NOT_APPLICABLE
                if requirement.media_type != "application/json"
                else SchemaSupport.NOT_DECLARED
            ),
            issues=["EVIDENCE_MUST_BE_REGULAR_NON_SYMLINK_FILE"],
        )
    size = source.stat().st_size
    if size > MAX_MEMBER_BYTES:
        return PreflightMember(
            **requirement.model_dump(mode="json"),
            availability=Availability.INVALID_LOCAL_OBJECT,
            schema_support=(
                SchemaSupport.NOT_APPLICABLE
                if requirement.media_type != "application/json"
                else SchemaSupport.NOT_DECLARED
            ),
            issues=["LIMIT_EXCEEDED:MEMBER_BYTES"],
        )
    if requirement.media_type == "application/json" and size > MAX_JSON_EVIDENCE_BYTES:
        return PreflightMember(
            **requirement.model_dump(mode="json"),
            availability=Availability.INVALID_LOCAL_OBJECT,
            schema_support=SchemaSupport.NOT_DECLARED,
            issues=["LIMIT_EXCEEDED:JSON_EVIDENCE_BYTES"],
        )
    raw = source.read_bytes() if requirement.media_type == "application/json" else b""
    if requirement.media_type == "application/json":
        support, issues, value = _schema_status(raw, requirement.phase, requirement.expected_schema)
    else:
        support, value = SchemaSupport.NOT_APPLICABLE, None
    observed_size, observed_digest = (
        (len(raw), hashlib.sha256(raw).hexdigest()) if raw else _hash_file(source)
    )
    semantic_status = VerdictStatus.NOT_TESTED
    semantic_summary = "Supporting evidence only."
    if requirement.verdict_role == VerdictRole.DIMENSION_VERDICT:
        if support == SchemaSupport.SUPPORTED_AND_VALID and value is not None:
            semantic_status, semantic_summary = project_semantic_status(value)
        else:
            semantic_status = VerdictStatus.UNKNOWN
            semantic_summary = "Evidence was unavailable or not semantically verifiable."
    return PreflightMember(
        **requirement.model_dump(mode="json"),
        availability=Availability.AVAILABLE,
        schema_support=support,
        size=observed_size,
        sha256=observed_digest,
        issues=issues,
        semantic_status=semantic_status,
        semantic_summary=semantic_summary,
    )


def build_preflight(request: AssuranceRequest, root: Path) -> AssurancePlan:
    members = [_inspect_member(root, item) for item in request.requirements]
    total = sum(item.size or 0 for item in members)
    if total > MAX_TOTAL_BYTES:
        raise OmivInputError("LIMIT_EXCEEDED:TOTAL_MEMBER_BYTES")
    expensive = {item.cost_class for item in request.planned_operations}
    costs = CostSummary(
        download=CostClass.DOWNLOAD in expensive,
        network=CostClass.NETWORK in expensive,
        conversion=CostClass.CONVERSION in expensive,
        gpu=CostClass.GPU in expensive,
        reasons=[item.reason for item in request.planned_operations],
    )
    required_blocker = any(
        item.required
        and (
            item.availability != Availability.AVAILABLE
            or item.schema_support
            not in {SchemaSupport.SUPPORTED_AND_VALID, SchemaSupport.NOT_APPLICABLE}
        )
        for item in members
    )
    has_gap = any(
        item.availability != Availability.AVAILABLE
        or item.schema_support in {SchemaSupport.NOT_DECLARED, SchemaSupport.UNSUPPORTED}
        for item in members
    )
    if required_blocker:
        status = PreflightStatus.BLOCKED
    elif any((costs.download, costs.network, costs.conversion, costs.gpu)):
        status = PreflightStatus.REVIEW_REQUIRED
    elif has_gap:
        status = PreflightStatus.READY_WITH_GAPS
    else:
        status = PreflightStatus.READY
    limitations = [
        "Preflight performs local bounded inspection only; it does not download, convert, "
        "use a network, or use a GPU.",
        "Bundle interoperability does not replace or upgrade Phase 5 or Phase 6A-6E "
        "semantic verdicts.",
    ]
    body: dict[str, Any] = {
        "schema": "omiv.assurance-plan.v1",
        "request_id": request.request_id,
        "subject": request.subject,
        "status": status.value,
        "members": [item.model_dump(mode="json") for item in members],
        "costs": costs.model_dump(mode="json"),
        "limitations": limitations,
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return AssurancePlan.model_validate(
        {**body, "plan_id": f"assurance_plan_{digest[:32]}", "plan_digest": digest}
    )


def write_plan(plan: AssurancePlan, output: Path) -> None:
    atomic_write_text(output, _pretty(plan))


def _finalized(
    model: type[BaseModel], body: dict[str, Any], id_field: str, digest_field: str, prefix: str
) -> BaseModel:
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return model.model_validate({**body, id_field: prefix + digest[:32], digest_field: digest})


def _core_documents(subject_name: str, members: list[BundleMember]) -> dict[str, BaseModel]:
    subject = _finalized(
        AssuranceSubjectDocument,
        {
            "schema": "omiv.assurance-subject.v1",
            "display_name": subject_name,
            "limitations": [
                "The bundle subject label is caller supplied and does not establish identity."
            ],
        },
        "subject_id",
        "subject_digest",
        "assurance_subject_",
    )
    index = _finalized(
        EvidenceIndexDocument,
        {
            "schema": "omiv.assurance-evidence-index.v1",
            "entries": [item.model_dump(mode="json") for item in members],
        },
        "index_id",
        "index_digest",
        "assurance_index_",
    )
    finding_records = [
        FindingRecord(
            code=issue,
            severity=(
                "ERROR"
                if item.required
                or item.schema_support == SchemaSupport.MISMATCH
                or item.availability == Availability.INVALID_LOCAL_OBJECT
                else "WARN"
            ),
            member_path=item.member_path,
            detail=item.semantic_summary,
        )
        for item in members
        for issue in item.issues
    ]
    findings = _finalized(
        FindingsDocument,
        {
            "schema": "omiv.assurance-findings.v1",
            "findings": [item.model_dump(mode="json") for item in finding_records],
        },
        "findings_id",
        "findings_digest",
        "assurance_findings_",
    )
    unknown_records = [
        UnknownRecord(
            member_path=item.member_path,
            dimension=item.dimension,
            required=item.required,
            reason=(
                item.semantic_summary
                if item.semantic_status == VerdictStatus.UNKNOWN
                else "; ".join(item.issues) or "Evidence is not available for verification."
            ),
            next_action=("Supply supported canonical evidence and rebuild the Assurance Bundle."),
        )
        for item in members
        if item.availability != Availability.AVAILABLE
        or item.schema_support
        in {
            SchemaSupport.NOT_DECLARED,
            SchemaSupport.UNSUPPORTED,
            SchemaSupport.MISMATCH,
        }
        or (
            item.verdict_role == VerdictRole.DIMENSION_VERDICT
            and item.semantic_status in {VerdictStatus.UNKNOWN, VerdictStatus.NOT_TESTED}
        )
    ]
    unknowns = _finalized(
        UnknownsDocument,
        {
            "schema": "omiv.assurance-unknowns.v1",
            "unknowns": [item.model_dump(mode="json") for item in unknown_records],
        },
        "unknowns_id",
        "unknowns_digest",
        "assurance_unknowns_",
    )
    dimension_verdicts: list[DimensionVerdict] = []
    for dimension in AssuranceDimension:
        selected = [
            item
            for item in members
            if item.dimension == dimension and item.verdict_role == VerdictRole.DIMENSION_VERDICT
        ]
        if not selected:
            continue
        statuses = {item.semantic_status for item in selected}
        if VerdictStatus.FAIL in statuses:
            status = VerdictStatus.FAIL
        elif VerdictStatus.WARN in statuses:
            status = VerdictStatus.WARN
        elif VerdictStatus.UNKNOWN in statuses or VerdictStatus.NOT_TESTED in statuses:
            status = VerdictStatus.UNKNOWN
        elif statuses == {VerdictStatus.PASS}:
            status = VerdictStatus.PASS
        else:
            status = VerdictStatus.UNKNOWN
        dimension_verdicts.append(
            DimensionVerdict(
                dimension=dimension,
                status=status,
                summary="; ".join(sorted({item.semantic_summary for item in selected})),
                evidence_paths=sorted(item.member_path for item in selected),
            )
        )
    if not dimension_verdicts:
        dimension_verdicts = [
            DimensionVerdict(
                dimension=AssuranceDimension.OTHER,
                status=VerdictStatus.NOT_TESTED,
                summary="No member was designated as a dimension verdict.",
                evidence_paths=[],
            )
        ]
    dimension_statuses = {item.status for item in dimension_verdicts}
    integrity_failures = sum(
        item.availability == Availability.INVALID_LOCAL_OBJECT
        or item.schema_support == SchemaSupport.MISMATCH
        for item in members
    )
    if integrity_failures or VerdictStatus.FAIL in dimension_statuses:
        overall = VerdictStatus.FAIL
    elif unknown_records or VerdictStatus.WARN in dimension_statuses:
        overall = VerdictStatus.WARN
    elif dimension_statuses == {VerdictStatus.PASS}:
        overall = VerdictStatus.PASS
    else:
        overall = VerdictStatus.UNKNOWN
    verdict = _finalized(
        AssuranceVerdictDocument,
        {
            "schema": "omiv.assurance-verdict.v1",
            "overall": overall.value,
            "dimensions": [item.model_dump(mode="json") for item in dimension_verdicts],
            "unresolved_claims": len(unknown_records),
            "integrity_failures": integrity_failures,
            "summary": (
                "Evidence was projected conservatively; UNKNOWN and NOT_TESTED were not "
                "promoted to PASS."
            ),
            "limitations": [
                "The concise verdict is derived from supplied canonical evidence only.",
                "Phase 6F does not replace the originating phase verifier or policy.",
            ],
        },
        "verdict_id",
        "verdict_digest",
        "assurance_verdict_",
    )
    capabilities = CapabilitiesDocument(
        features=list(FEATURES),
        transports=["DIRECTORY", "ZIP_STORED"],
        signature_algorithms=["ED25519"],
        supported_evidence_schemas=list(supported_schemas()),
        limits={
            "maximum_members": 256,
            "maximum_member_bytes": MAX_MEMBER_BYTES,
            "maximum_total_bytes": MAX_TOTAL_BYTES,
        },
    )
    return {
        "subject.json": subject,
        "verdict.json": verdict,
        "evidence-index.json": index,
        "findings.json": findings,
        "unknowns.json": unknowns,
        "capabilities.json": capabilities,
    }


def _manifest_from_plan(
    plan: AssurancePlan, members: list[BundleMember], core_files: list[CoreFileRecord]
) -> AssuranceBundleManifest:
    complete = all(
        item.availability == Availability.AVAILABLE
        and item.schema_support in {SchemaSupport.SUPPORTED_AND_VALID, SchemaSupport.NOT_APPLICABLE}
        for item in members
    )
    body: dict[str, Any] = {
        "schema": "omiv.assurance-bundle.v1",
        "subject": plan.subject,
        "source_plan_id": plan.plan_id,
        "source_plan_digest": plan.plan_digest,
        "preflight_status": plan.status.value,
        "status": (BundleStatus.COMPLETE if complete else BundleStatus.INCOMPLETE).value,
        "members": [item.model_dump(mode="json") for item in members],
        "core_files": [item.model_dump(mode="json") for item in core_files],
        "bundle_profile": "omiv.assurance-bundle.v1",
        "required_features": list(FEATURES),
        "costs": plan.costs.model_dump(mode="json"),
        "limitations": plan.limitations,
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return AssuranceBundleManifest.model_validate(
        {**body, "bundle_id": f"assurance_bundle_{digest[:32]}", "bundle_digest": digest}
    )


def build_bundle(plan: AssurancePlan, root: Path, output: Path) -> AssuranceBundleManifest:
    if output.exists() or output.is_symlink():
        raise OmivInputError("Assurance Bundle output directory must not already exist")
    parent = output.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        members = [
            BundleMember.model_validate(item.model_dump(mode="json", exclude={"source_path"}))
            for item in plan.members
        ]
        for member in plan.members:
            if member.availability != Availability.AVAILABLE:
                continue
            source = _safe_source(root, member.source_path)
            if source.is_symlink() or not source.is_file():
                raise OmivInputError(f"evidence changed after preflight: {member.source_path}")
            observed_size, observed_digest = _hash_file(source)
            if observed_size != member.size or observed_digest != member.sha256:
                raise OmivInputError(f"evidence changed after preflight: {member.source_path}")
            destination = temporary / Path(*member.member_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as source_handle, destination.open("wb") as output_handle:
                shutil.copyfileobj(source_handle, output_handle, length=1024 * 1024)
        core_documents = _core_documents(plan.subject, members)
        core_files: list[CoreFileRecord] = []
        for path, document in core_documents.items():
            raw = _pretty(document).encode("utf-8")
            (temporary / path).write_bytes(raw)
            core_files.append(
                CoreFileRecord(
                    path=path,
                    schema_id=document.model_dump(mode="json", by_alias=True)["schema"],
                    size=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                )
            )
        manifest = _manifest_from_plan(plan, members, core_files)
        (temporary / MANIFEST_NAME).write_text(_pretty(manifest), encoding="utf-8")
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def verify_bundle(root: Path) -> AssuranceVerificationReport:
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("Assurance Bundle root must be a regular non-symlink directory")
    manifest = load_manifest(root / MANIFEST_NAME)
    if manifest.bundle_profile != "omiv.assurance-bundle.v1" or not set(
        manifest.required_features
    ).issubset(FEATURES):
        raise OmivInputError("unsupported Assurance Bundle profile or required feature")
    expected_files = {
        item.member_path for item in manifest.members if item.availability == Availability.AVAILABLE
    } | {item.path for item in manifest.core_files}
    bundle_paths = list(root.rglob("*"))
    signature_files = {
        path.relative_to(root).as_posix()
        for path in bundle_paths
        if path.is_file() and path.parent == root / "signatures" and path.suffix == ".json"
    }
    actual_files = {
        path.relative_to(root).as_posix()
        for path in bundle_paths
        if path.is_file()
        and path.relative_to(root).as_posix() != MANIFEST_NAME
        and path.relative_to(root).as_posix() not in signature_files
    }
    findings: list[VerificationFinding] = []
    core_file_set_valid = {item.path for item in manifest.core_files} == set(CORE_FILES)
    if not core_file_set_valid:
        findings.append(
            VerificationFinding(
                code="CORE_FILE_SET_MISMATCH",
                detail="the v1 profile requires exactly the six canonical core documents",
            )
        )
    symlinks = [path.relative_to(root).as_posix() for path in bundle_paths if path.is_symlink()]
    if symlinks:
        findings.append(
            VerificationFinding(
                code="BUNDLE_SYMLINK_PRESENT",
                detail=f"observed {len(symlinks)} symbolic links",
            )
        )
    if actual_files != expected_files:
        findings.append(
            VerificationFinding(
                code="BUNDLE_FILE_SET_MISMATCH",
                detail=(
                    f"expected {len(expected_files)} payload files, observed {len(actual_files)}"
                ),
            )
        )
    available = missing = unknown = 0
    invalid = int(not core_file_set_valid)
    parsed_core: dict[str, BaseModel] = {}
    for core in manifest.core_files:
        target = root / core.path
        if target.is_symlink() or not target.is_file():
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=core.path,
                    code="CORE_FILE_MISSING",
                    detail="required Phase 6F core document is unavailable",
                )
            )
            continue
        if target.stat().st_size > MAX_CONTROL_BYTES:
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=core.path,
                    code="LIMIT_EXCEEDED:CORE_FILE_BYTES",
                    detail="core document exceeds the bounded parser limit",
                )
            )
            continue
        raw = target.read_bytes()
        if len(raw) != core.size or hashlib.sha256(raw).hexdigest() != core.sha256:
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=core.path,
                    code="CORE_FILE_INTEGRITY_MISMATCH",
                    detail="size or SHA-256 differs from the manifest",
                )
            )
            continue
        try:
            value = load_json_value(raw.decode("utf-8"))
            model = CORE_MODELS.get(core.schema_id)
            if (
                not isinstance(value, dict)
                or model is None
                or value.get("schema") != core.schema_id
            ):
                raise ValueError("unsupported core schema")
            parsed_core[core.path] = model.model_validate(value)
        except (UnicodeError, OmivInputError, ValidationError, ValueError) as exc:
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=core.path,
                    code="CORE_FILE_SCHEMA_INVALID",
                    detail=str(exc),
                )
            )
    parsed_subject = parsed_core.get("subject.json")
    if isinstance(parsed_subject, AssuranceSubjectDocument):
        expected_core = _core_documents(parsed_subject.display_name, manifest.members)
        for path, expected in expected_core.items():
            actual = parsed_core.get(path)
            if actual is None or actual.model_dump(
                mode="json", by_alias=True
            ) != expected.model_dump(mode="json", by_alias=True):
                invalid += 1
                findings.append(
                    VerificationFinding(
                        member_path=path,
                        code="CORE_PROJECTION_MISMATCH",
                        detail="core document does not reconstruct from indexed evidence",
                    )
                )
    observed_total = 0
    for member in manifest.members:
        target = root / Path(*member.member_path.split("/"))
        if member.availability != Availability.AVAILABLE:
            missing += 1
            findings.append(
                VerificationFinding(
                    member_path=member.member_path,
                    code="EVIDENCE_MISSING",
                    detail="required" if member.required else "optional",
                )
            )
            if target.exists():
                invalid += 1
            continue
        if target.is_symlink() or not target.is_file():
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=member.member_path,
                    code="EVIDENCE_FILE_INVALID",
                    detail="expected a regular non-symlink file",
                )
            )
            continue
        if target.stat().st_size > MAX_MEMBER_BYTES:
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=member.member_path,
                    code="LIMIT_EXCEEDED:MEMBER_BYTES",
                    detail="evidence exceeds the portable member limit",
                )
            )
            continue
        observed_size, observed_digest = _hash_file(target)
        observed_total += observed_size
        if observed_size != member.size or observed_digest != member.sha256:
            invalid += 1
            findings.append(
                VerificationFinding(
                    member_path=member.member_path,
                    code="EVIDENCE_INTEGRITY_MISMATCH",
                    detail="size or SHA-256 differs from the manifest",
                )
            )
            continue
        if member.media_type == "application/json":
            if observed_size > MAX_JSON_EVIDENCE_BYTES:
                invalid += 1
                findings.append(
                    VerificationFinding(
                        member_path=member.member_path,
                        code="LIMIT_EXCEEDED:JSON_EVIDENCE_BYTES",
                        detail="JSON evidence exceeds the bounded parser limit",
                    )
                )
                continue
            raw = target.read_bytes()
            support, issues, value = _schema_status(raw, member.phase, member.expected_schema)
            if support != SchemaSupport.SUPPORTED_AND_VALID:
                unknown += int(support in {SchemaSupport.NOT_DECLARED, SchemaSupport.UNSUPPORTED})
                invalid += int(support == SchemaSupport.MISMATCH)
                findings.extend(
                    VerificationFinding(
                        member_path=member.member_path,
                        code=issue,
                        detail=support.value,
                    )
                    for issue in issues
                )
                continue
            if member.verdict_role == VerdictRole.DIMENSION_VERDICT:
                if value is None:
                    invalid += 1
                    findings.append(
                        VerificationFinding(
                            member_path=member.member_path,
                            code="SEMANTIC_PROJECTION_UNAVAILABLE",
                            detail="validated verdict evidence did not produce a canonical object",
                        )
                    )
                    continue
                semantic_status, semantic_summary = project_semantic_status(value)
                if (
                    semantic_status != member.semantic_status
                    or semantic_summary != member.semantic_summary
                ):
                    invalid += 1
                    findings.append(
                        VerificationFinding(
                            member_path=member.member_path,
                            code="SEMANTIC_PROJECTION_MISMATCH",
                            detail=(
                                "manifest verdict projection does not reconstruct from "
                                "canonical evidence"
                            ),
                        )
                    )
                    continue
        available += 1
    if observed_total > MAX_TOTAL_BYTES:
        invalid += 1
        findings.append(
            VerificationFinding(
                code="LIMIT_EXCEEDED:TOTAL_MEMBER_BYTES",
                detail="evidence exceeds the portable bundle total limit",
            )
        )
    if invalid or symlinks or actual_files != expected_files or not core_file_set_valid:
        status = BundleStatus.INVALID
    elif missing or unknown or manifest.status != BundleStatus.COMPLETE:
        status = BundleStatus.INCOMPLETE
    else:
        status = BundleStatus.COMPLETE
    return AssuranceVerificationReport(
        bundle_id=manifest.bundle_id,
        bundle_digest=manifest.bundle_digest,
        status=status,
        available=available,
        missing=missing,
        unknown=unknown,
        invalid=invalid,
        findings=findings,
        evidence={
            "offline": True,
            "manifest_member_count": len(manifest.members),
            "payload_file_count": len(actual_files),
            "detached_signature_file_count": len(signature_files),
            "phase_boundaries_preserved": True,
        },
    )


def write_verification_report(report: AssuranceVerificationReport, output: Path) -> None:
    atomic_write_text(output, _pretty(report))


def concise_plan_summary(plan: AssurancePlan) -> str:
    missing = sum(item.availability != Availability.AVAILABLE for item in plan.members)
    unknown = sum(
        item.schema_support in {SchemaSupport.NOT_DECLARED, SchemaSupport.UNSUPPORTED}
        for item in plan.members
    )
    costly = [
        name
        for name, enabled in (
            ("download", plan.costs.download),
            ("network", plan.costs.network),
            ("conversion", plan.costs.conversion),
            ("gpu", plan.costs.gpu),
        )
        if enabled
    ]
    return (
        f"{plan.status.value} members={len(plan.members)} missing={missing} unknown={unknown} "
        f"costly={','.join(costly) if costly else 'none'}"
    )


def concise_bundle_summary(manifest: AssuranceBundleManifest) -> str:
    missing = sum(item.availability != Availability.AVAILABLE for item in manifest.members)
    unknown = sum(
        item.schema_support in {SchemaSupport.NOT_DECLARED, SchemaSupport.UNSUPPORTED}
        for item in manifest.members
    )
    return (
        f"{manifest.status.value} bundle={manifest.bundle_id} members={len(manifest.members)} "
        f"missing={missing} unknown={unknown}"
    )


def concise_verification_summary(report: AssuranceVerificationReport) -> str:
    return (
        f"{report.status.value} bundle={report.bundle_id} available={report.available} "
        f"missing={report.missing} unknown={report.unknown} invalid={report.invalid}"
    )
