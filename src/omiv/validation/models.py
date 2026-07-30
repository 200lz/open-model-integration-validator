"""Strict models for independent validation inventories and reports."""

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel

VALIDATION_SCHEMA = "omiv.independent-model-validation.v1"
VALIDATION_REPORT_SCHEMA = "omiv.independent-model-validation-report.v1"
PROFILE_POLICY_SCHEMA = "omiv.validation-acceptance-profile-policy.v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class EvidenceStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"


class EvidenceStageName(StrEnum):
    REPOSITORY_IDENTITY = "repository_identity"
    REPOSITORY_LAYOUT = "repository_layout"
    RANGE_SEMANTICS = "range_semantics"
    FILE_PREFIX = "file_prefix"
    COMPLETE_HEADER = "complete_header"
    SPLIT_CONTAINER = "split_container"
    PAYLOAD_SPAN_BOUNDS = "payload_span_bounds"
    TARGET_ONTOLOGY = "target_ontology"
    STRUCTURAL_SEMANTIC_MAPPING = "structural_semantic_mapping"
    CONVERTER_RULE_SUPPORT = "converter_rule_support"
    DETERMINISTIC_VERIFICATION = "deterministic_verification"
    ARTIFACT_SPECIFIC_PROVENANCE = "artifact_specific_provenance"
    PAYLOAD_INTEGRITY = "payload_integrity"
    QUANTIZATION_FIDELITY = "quantization_fidelity"
    TOKENIZER_PARITY = "tokenizer_parity"
    RUNTIME_PARITY = "runtime_parity"


class ProfileRequirement(StrEnum):
    REQUIRED_PASS = "required_pass"
    ALLOWED_WARN = "allowed_warn"
    ALLOWED_UNAVAILABLE = "allowed_unavailable"
    REQUIRED_CHECKED = "required_checked"
    NOT_REQUIRED = "not_required"


class ProfileOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    SATISFIED_WITH_WARNINGS = "SATISFIED_WITH_WARNINGS"
    NOT_SATISFIED = "NOT_SATISFIED"


class StructuralValidationResult(StrEnum):
    VALIDATED_WITH_LIMITATIONS = "STRUCTURALLY_VALIDATED_WITH_LIMITATIONS"
    FAILED = "STRUCTURAL_VALIDATION_FAILED"


class SubjectIdentity(StrictModel):
    model_family: str
    artifact_variant: str
    repository: str


class RepositoryIdentity(StrictModel):
    provider: str
    repository: str
    requested_revision: str
    resolved_revision: str
    selection: str


class ModelPackIdentity(StrictModel):
    model_family: str
    version: int = Field(ge=1)
    capabilities: list[str]
    digest: str = Field(pattern=SHA256_PATTERN)
    ontology_policy_digest: str = Field(pattern=SHA256_PATTERN)
    mapping_policy_digest: str = Field(pattern=SHA256_PATTERN)
    converter_evidence_revision: str = Field(pattern=r"^[0-9a-f]{40}$")


class EvidenceNode(StrictModel):
    node_id: str
    artifact_kind: str
    schema_id: str
    canonical_digest: str = Field(pattern=SHA256_PATTERN)
    artifact_identifier: str
    verification_status: EvidenceStatus
    provider: str | None = None
    model_identity: str | None = None
    parent_dependency_digests: list[str] = Field(default_factory=list)
    policy_digests: list[str] = Field(default_factory=list)
    model_pack_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    evidence_scope: list[str]
    evidence_limitations: list[str]


class EvidenceEdge(StrictModel):
    parent_node_id: str
    child_node_id: str
    dependency_relation: str
    expected_digest: str = Field(pattern=SHA256_PATTERN)
    observed_digest: str = Field(pattern=SHA256_PATTERN)
    linkage_status: EvidenceStatus
    mismatch_reason: str | None = None


class EvidenceStageResult(StrictModel):
    stage: EvidenceStageName
    status: EvidenceStatus
    evidence_node_ids: list[str]
    finding_ids: list[str]
    artifact_digests: list[str]
    policy_digests: list[str]
    scope: list[str]
    limitations: list[str]
    next_required_evidence: list[str]


class AcceptanceProfile(StrictModel):
    name: str
    description: str
    requirements: dict[EvidenceStageName, ProfileRequirement]


class AcceptanceProfilePolicy(StrictModel):
    schema_id: Literal["omiv.validation-acceptance-profile-policy.v1"] = (
        "omiv.validation-acceptance-profile-policy.v1"
    )
    profiles: list[AcceptanceProfile]
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class ProfileStageDecision(StrictModel):
    stage: EvidenceStageName
    requirement: ProfileRequirement
    observed_status: EvidenceStatus
    satisfied: bool
    warning: bool
    reason: str


class ProfileResult(StrictModel):
    profile_name: str
    outcome: ProfileOutcome
    satisfied: bool
    warning_count: int = Field(ge=0)
    failed_requirement_count: int = Field(ge=0)
    decisions: list[ProfileStageDecision]


class ArtifactIndexEntry(StrictModel):
    role: str
    schema_id: str
    relative_path: str
    canonical_digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    required: bool
    producer_phase: str
    verification_command: str

    @model_validator(mode="after")
    def relative_posix_path(self) -> "ArtifactIndexEntry":
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
            raise ValueError("artifact paths must be repository-relative POSIX paths")
        return self


class ArtifactIndex(StrictModel):
    entries: list[ArtifactIndexEntry]
    index_digest: str = Field(pattern=SHA256_PATTERN)


class Finding(StrictModel):
    finding_id: str
    status: EvidenceStatus
    summary: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    limitation: str | None = None


class ReproductionCommand(StrictModel):
    command: str
    network_requirement: Literal["online", "offline"]
    purpose: str


class ReproductionManifest(StrictModel):
    omiv_repository_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    original_evidence_commands: list[ReproductionCommand]
    offline_verification_commands: list[ReproductionCommand]
    required_input_paths: list[str]
    expected_input_digests: dict[str, str]
    original_remote_header_bytes_accepted: int = Field(ge=0)
    original_range_request_count: int = Field(ge=0)
    tensor_payload_bytes_accepted: int = Field(ge=0)
    no_payload_download: bool


class ValidationInventory(StrictModel):
    schema_id: Literal["omiv.independent-model-validation.v1"] = (
        "omiv.independent-model-validation.v1"
    )
    subject: SubjectIdentity
    repository_identity: RepositoryIdentity
    source_artifact_identity: dict[str, JsonValue]
    target_artifact_identity: dict[str, JsonValue]
    model_pack_identity: ModelPackIdentity
    evidence_nodes: list[EvidenceNode]
    evidence_edges: list[EvidenceEdge]
    evidence_stages: list[EvidenceStageResult]
    evidence_graph_digest: str = Field(pattern=SHA256_PATTERN)
    profile_policy: AcceptanceProfilePolicy
    profile_results: list[ProfileResult]
    selected_profile: str
    structural_validation_result: StructuralValidationResult
    unverified_stage_count: int = Field(ge=0)
    unavailable_stage_count: int = Field(ge=0)
    failed_stage_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    repository_summary: dict[str, JsonValue]
    architecture_summary: dict[str, JsonValue]
    source_accounting: dict[str, JsonValue]
    target_accounting: dict[str, JsonValue]
    mapping_domain_summary: list[dict[str, JsonValue]]
    verified_scope: list[str]
    not_verified_scope: list[str]
    limitations: list[str]
    findings: list[Finding]
    reproduction: ReproductionManifest
    artifact_index: ArtifactIndex
    inventory_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def internal_uniqueness(self) -> "ValidationInventory":
        node_ids = [node.node_id for node in self.evidence_nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("duplicate evidence node identity")
        stage_ids = [stage.stage for stage in self.evidence_stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("duplicate evidence stage")
        profile_names = [result.profile_name for result in self.profile_results]
        if len(profile_names) != len(set(profile_names)):
            raise ValueError("duplicate profile result")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("duplicate finding identity")
        edge_keys = [
            (edge.parent_node_id, edge.child_node_id, edge.dependency_relation)
            for edge in self.evidence_edges
        ]
        if len(edge_keys) != len(set(edge_keys)):
            raise ValueError("duplicate evidence edge")
        known = set(node_ids)
        if any(
            edge.parent_node_id not in known or edge.child_node_id not in known
            for edge in self.evidence_edges
        ):
            raise ValueError("evidence edge references an unknown node")
        indegree = {node_id: 0 for node_id in node_ids}
        children: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
        for edge in self.evidence_edges:
            indegree[edge.child_node_id] += 1
            children[edge.parent_node_id].append(edge.child_node_id)
        queue = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
        visited: list[str] = []
        while queue:
            node_id = queue.pop(0)
            visited.append(node_id)
            for child in sorted(children[node_id]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
                    queue.sort()
        if len(visited) != len(node_ids):
            raise ValueError("evidence graph contains a cycle")
        return self


class ValidationReport(StrictModel):
    report_schema: Literal["omiv.independent-model-validation-report.v1"] = (
        "omiv.independent-model-validation-report.v1"
    )
    inventory: ValidationInventory
    executive_summary: dict[str, JsonValue]
    engineering_summary: dict[str, JsonValue]
    commercial_acceptance_matrix: list[dict[str, JsonValue]]
    validation_stage_matrix: list[dict[str, JsonValue]]
    acceptance_profile_matrix: list[dict[str, JsonValue]]
    report_digest: str = Field(pattern=SHA256_PATTERN)


class ValidationReportEnvelope(StrictModel):
    report: ValidationReport
    integrity: dict[str, str]


def digest_without_field(model: StrictModel, field: str) -> str:
    data = model.model_dump(mode="json")
    data.pop(field, None)
    return canonical_sha256(data)
