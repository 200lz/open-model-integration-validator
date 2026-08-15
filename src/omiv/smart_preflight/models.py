"""Strict models for the candidate Phase 7A local auto planner."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from omiv.assurance.models import AssuranceDimension, AssuranceRequest, EvidencePhase, VerdictRole
from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path

MAX_SEARCH_PATHS = 32
MAX_CANDIDATES = 512
MAX_FINDINGS = 512


class SmartPreflightStatus(StrEnum):
    READY = "READY"
    READY_WITH_GAPS = "READY_WITH_GAPS"
    BLOCKED = "BLOCKED"


class CoverageStatus(StrEnum):
    COVERED = "COVERED"
    MISSING = "MISSING"
    AMBIGUOUS = "AMBIGUOUS"


class FindingSeverity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class SmartPreflightIntent(StrictModel):
    schema_id: Literal["omiv.smart-preflight-intent.v1"] = Field(
        default="omiv.smart-preflight-intent.v1", alias="schema"
    )
    intent_id: str = Field(min_length=3, max_length=96, pattern=r"^[A-Za-z0-9._-]+$")
    subject: str = Field(min_length=1, max_length=1000)
    search_paths: list[str] = Field(default_factory=lambda: ["."], max_length=MAX_SEARCH_PATHS)
    required_dimensions: list[AssuranceDimension] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_search_scope(self) -> SmartPreflightIntent:
        if not self.search_paths:
            raise ValueError("Smart Preflight requires at least one search path")
        if len(set(self.required_dimensions)) != len(self.required_dimensions):
            raise ValueError("required dimensions must be unique")
        if "." in self.search_paths:
            if self.search_paths != ["."]:
                raise ValueError("root search path cannot be combined with narrower paths")
        else:
            validate_path_set(tuple(self.search_paths))
        return self


class DiscoveryCandidate(StrictModel):
    source_path: str
    schema_id: str = Field(max_length=200)
    phase: EvidencePhase
    dimension: AssuranceDimension
    proposed_verdict_role: VerdictRole
    member_path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected: bool
    selection_reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_paths(self) -> DiscoveryCandidate:
        validate_portable_path(self.source_path)
        validate_portable_path(self.member_path)
        return self


class DimensionCoverage(StrictModel):
    dimension: AssuranceDimension
    status: CoverageStatus
    candidate_paths: list[str] = Field(max_length=MAX_CANDIDATES)
    selected_path: str | None = None

    @model_validator(mode="after")
    def validate_selection(self) -> DimensionCoverage:
        for path in self.candidate_paths:
            validate_portable_path(path)
        if self.status == CoverageStatus.COVERED:
            if self.selected_path is None or self.selected_path not in self.candidate_paths:
                raise ValueError("covered dimension requires a selected candidate")
        elif self.selected_path is not None:
            raise ValueError("uncovered dimension cannot claim a selected candidate")
        return self


class DiscoveryFinding(StrictModel):
    code: str = Field(min_length=1, max_length=200)
    severity: FindingSeverity
    detail: str = Field(min_length=1, max_length=1000)
    source_path: str | None = None

    @model_validator(mode="after")
    def validate_source_path(self) -> DiscoveryFinding:
        if self.source_path is not None:
            validate_portable_path(self.source_path)
        return self


class SmartCostSummary(StrictModel):
    inspected_entries: int = Field(ge=0)
    inspected_json_files: int = Field(ge=0)
    inspected_json_bytes: int = Field(ge=0)
    download: Literal[False] = False
    network: Literal[False] = False
    conversion: Literal[False] = False
    remote_collector: Literal[False] = False
    gpu: Literal[False] = False


class SmartPreflightPlan(StrictModel):
    schema_id: Literal["omiv.smart-preflight-plan.v1"] = Field(
        default="omiv.smart-preflight-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    intent: SmartPreflightIntent
    status: SmartPreflightStatus
    candidates: list[DiscoveryCandidate] = Field(max_length=MAX_CANDIDATES)
    coverage: list[DimensionCoverage] = Field(max_length=32)
    assurance_request: AssuranceRequest | None
    findings: list[DiscoveryFinding] = Field(max_length=MAX_FINDINGS)
    costs: SmartCostSummary
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_identity_and_handoff(self) -> SmartPreflightPlan:
        body = self.model_dump(mode="json", by_alias=True, exclude={"plan_id", "plan_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.plan_digest != digest or self.plan_id != f"smart_plan_{digest[:32]}":
            raise ValueError("Smart Preflight Plan canonical identity mismatch")
        selected = [item for item in self.candidates if item.selected]
        if (self.assurance_request is None) != (not selected):
            raise ValueError("Assurance request must exactly reflect selected candidates")
        if self.assurance_request is not None:
            expected = {
                (
                    item.source_path,
                    item.member_path,
                    item.schema_id,
                    item.phase,
                    item.dimension,
                    VerdictRole.DIMENSION_VERDICT,
                )
                for item in selected
            }
            actual = {
                (
                    item.source_path,
                    item.member_path,
                    item.expected_schema,
                    item.phase,
                    item.dimension,
                    item.verdict_role,
                )
                for item in self.assurance_request.requirements
            }
            if actual != expected:
                raise ValueError("Assurance request does not match selected candidates")
            if (
                self.assurance_request.subject != self.intent.subject
                or self.assurance_request.request_id != f"smart-{self.intent.intent_id}"
                or self.assurance_request.planned_operations
            ):
                raise ValueError("Assurance request does not preserve the local intent boundary")
        return self
