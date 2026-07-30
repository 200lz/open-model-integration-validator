"""Strict schemas for evidence-linked technical publication packages."""

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from omiv.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ClaimClass(StrEnum):
    VERIFIED_FACT = "verified_fact"
    STRUCTURAL_CONCLUSION = "structural_conclusion"
    DIAGNOSTIC_OBSERVATION = "diagnostic_observation"
    INFERENCE = "inference"
    LIMITATION = "limitation"
    FUTURE_WORK = "future_work"
    UNSUPPORTED = "unsupported"


class ArticleArtifact(StrictModel):
    role: str
    schema_id: str
    relative_path: str
    canonical_digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    required: bool
    producer_phase: str
    verification_command: str

    @model_validator(mode="after")
    def safe_path(self) -> "ArticleArtifact":
        if self.relative_path.startswith("/") or "\\" in self.relative_path:
            raise ValueError("article artifact paths must be relative POSIX paths")
        if ".." in self.relative_path.split("/"):
            raise ValueError("article artifact paths cannot traverse parents")
        return self


class PublicClaim(StrictModel):
    claim_id: str = Field(pattern=r"^CLAIM-[0-9]{3}$")
    short_title: str
    claim_text: str
    claim_class: ClaimClass
    evidence_stage: str
    supporting_artifact_digests: list[str]
    supporting_finding_ids: list[str]
    supporting_policy_digests: list[str]
    confidence_category: Literal["verified", "structural", "explicit_boundary"]
    allowed_wording: list[str]
    forbidden_wording: list[str]
    limitations: list[str]
    publication_destinations: list[str]
    verification_status: Literal["verified", "explicit_limitation", "unsupported"]

    @model_validator(mode="after")
    def classification_consistent(self) -> "PublicClaim":
        if self.claim_class == ClaimClass.UNSUPPORTED and self.verification_status != "unsupported":
            raise ValueError("unsupported claims cannot be verified")
        if self.verification_status == "verified" and not self.supporting_artifact_digests:
            raise ValueError("verified claims require supporting artifacts")
        return self


class PublicClaimRegistry(StrictModel):
    schema_id: Literal["omiv.public-claim-registry.v1"] = "omiv.public-claim-registry.v1"
    article_id: Literal["kimi-k3-gguf-validation"] = "kimi-k3-gguf-validation"
    claims: list[PublicClaim]
    globally_forbidden_wording: list[str]
    registry_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def unique_sorted_claims(self) -> "PublicClaimRegistry":
        ids = [item.claim_id for item in self.claims]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("claims must have unique deterministic ordering")
        return self


class ReproductionCommand(StrictModel):
    order: int = Field(ge=1)
    phase: str
    command: str
    network_required: bool
    expected_exit_code: int = Field(ge=0, le=2)
    expected_status: str

    @model_validator(mode="after")
    def safe_command(self) -> "ReproductionCommand":
        forbidden = ("Authorization", "Bearer ", "curl ", "wget ", "/home/", "http://")
        if any(value in self.command for value in forbidden):
            raise ValueError("unsafe reproduction command")
        return self


class ArticleReproducibilityManifest(StrictModel):
    schema_id: Literal["omiv.article-reproducibility-manifest.v1"] = (
        "omiv.article-reproducibility-manifest.v1"
    )
    repository: str
    resolved_revision: str
    omiv_repository_commit: str
    required_software_assumptions: list[str]
    commands: list[ReproductionCommand]
    expected_artifact_paths: list[str]
    expected_digests: dict[str, str]
    expected_remote_header_bytes: dict[str, int]
    expected_tensor_payload_bytes_accepted: int
    known_provider_limitations: list[str]
    reproducibility_digest: str = Field(pattern=SHA256_PATTERN)


class ArticleEvidenceManifest(StrictModel):
    schema_id: Literal["omiv.article-evidence-manifest.v1"] = "omiv.article-evidence-manifest.v1"
    article_id: Literal["kimi-k3-gguf-validation"] = "kimi-k3-gguf-validation"
    subject: str
    repository: str
    resolved_revision: str
    baseline_commit: str
    model_pack_identity: dict[str, object]
    converter_evidence_identity: dict[str, str]
    canonical_artifacts: list[ArticleArtifact]
    report_envelope_digests: dict[str, str]
    evidence_graph_digests: dict[str, str]
    policy_digests: dict[str, str]
    claim_registry_digest: str = Field(pattern=SHA256_PATTERN)
    reproducibility_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    supported_evidence_stages: list[str]
    unavailable_evidence_stages: list[str]
    not_checked_evidence_stages: list[str]
    manifest_digest: str = Field(pattern=SHA256_PATTERN)


class ArticleIndexEntry(StrictModel):
    role: str
    schema_id: str
    relative_path: str
    digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    required: bool
    verification_command: str


class ArticleArtifactIndex(StrictModel):
    schema_id: Literal["omiv.article-artifact-index.v1"] = "omiv.article-artifact-index.v1"
    entries: list[ArticleIndexEntry]
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def deterministic_entries(self) -> "ArticleArtifactIndex":
        paths = [item.relative_path for item in self.entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("article index paths must be unique and sorted")
        return self
