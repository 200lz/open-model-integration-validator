"""Build publication evidence directly from verified canonical artifacts."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

from omiv.article.models import (
    ArticleArtifact,
    ArticleArtifactIndex,
    ArticleEvidenceManifest,
    ArticleIndexEntry,
    ArticleReproducibilityManifest,
    ClaimClass,
    PublicClaim,
    PublicClaimRegistry,
    ReproductionCommand,
)
from omiv.canonical import canonical_sha256
from omiv.comparison.reporting import verify_comparison_inventory
from omiv.errors import OmivInputError
from omiv.validation.reporting import verify_validation_inventory

BASELINE_COMMIT = "82db9f9f9465a20286d25de875d02d90bc3de871"
REVISION = "3d4b61ab4b6789d401191c476cbb4567246db8f5"
CONVERTER_REVISION = "cf67f0d24511864d2d3da0769108fd6fc16d00d1"
IQ_VALIDATION = "validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json"
Q4_VALIDATION = "validations/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.validation.inventory.json"
COMPARISON = "comparisons/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.inventory.json"
IQ_REPORT = "reports/validation/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.report.json"
Q4_REPORT = "reports/validation/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.validation.report.json"
COMPARISON_REPORT = (
    "reports/comparison/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.report.json"
)
CLAIM_PATH = "articles/evidence/kimi-k3-gguf-validation.claim-registry.json"
REPRO_PATH = "articles/evidence/kimi-k3-gguf-validation.reproducibility.json"
MANIFEST_PATH = "articles/evidence/kimi-k3-gguf-validation.evidence-manifest.json"
INDEX_PATH = "articles/evidence/kimi-k3-gguf-validation.article-artifact-index.json"


def _digest_model(model: Any, field: str) -> str:
    data = model.model_dump(mode="json")
    data.pop(field, None)
    return canonical_sha256(data)


def _raw_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _claim(
    number: int,
    title: str,
    text: str,
    kind: ClaimClass,
    stage: str,
    artifacts: list[str],
    findings: list[str],
    policies: list[str],
    *,
    limitation: str = "This claim is limited to structural evidence.",
) -> PublicClaim:
    boundary = kind == ClaimClass.LIMITATION
    return PublicClaim(
        claim_id=f"CLAIM-{number:03d}",
        short_title=title,
        claim_text=text,
        claim_class=kind,
        evidence_stage=stage,
        supporting_artifact_digests=artifacts,
        supporting_finding_ids=findings,
        supporting_policy_digests=policies,
        confidence_category="explicit_boundary"
        if boundary
        else ("structural" if kind == ClaimClass.STRUCTURAL_CONCLUSION else "verified"),
        allowed_wording=[text],
        forbidden_wording=[],
        limitations=[limitation],
        publication_destinations=[
            "technical_article",
            "community_release_notes",
            "social_draft",
        ],
        verification_status="explicit_limitation" if boundary else "verified",
    )


def _verified(root: Path) -> tuple[Any, Any, Any]:
    iq = verify_validation_inventory(root / IQ_VALIDATION, root)
    q4 = verify_validation_inventory(root / Q4_VALIDATION, root)
    comparison = verify_comparison_inventory(root / COMPARISON, root)
    if iq.repository_identity.resolved_revision != REVISION:
        raise OmivInputError("IQ1_M immutable revision mismatch")
    if q4.repository_identity.resolved_revision != REVISION:
        raise OmivInputError("Q4 immutable revision mismatch")
    if comparison.baseline.resolved_revision != comparison.candidate.resolved_revision:
        raise OmivInputError("comparison revisions differ")
    return iq, q4, comparison


def validate_claim_support(
    claims: list[PublicClaim],
    *,
    artifact_digests: set[str],
    finding_ids: set[str],
    policy_digests: set[str],
) -> None:
    """Reject claims whose declared support is absent from verified evidence."""
    for claim in claims:
        missing_artifacts = set(claim.supporting_artifact_digests) - artifact_digests
        missing_findings = set(claim.supporting_finding_ids) - finding_ids
        missing_policies = set(claim.supporting_policy_digests) - policy_digests
        if missing_artifacts or missing_findings or missing_policies:
            raise OmivInputError(
                f"{claim.claim_id} has missing support: "
                f"artifacts={sorted(missing_artifacts)}, "
                f"findings={sorted(missing_findings)}, "
                f"policies={sorted(missing_policies)}"
            )


def build_claim_registry(root: Path) -> PublicClaimRegistry:
    iq, q4, comp = _verified(root)
    iq_digest = iq.inventory_digest
    q4_digest = q4.inventory_digest
    comp_digest = comp.comparison_digest
    artifacts = [iq_digest, q4_digest, comp_digest]
    ontology = iq.model_pack_identity.ontology_policy_digest
    mapping = iq.model_pack_identity.mapping_policy_digest
    comparison_policy = comp.policy.policy_digest
    structural = ClaimClass.STRUCTURAL_CONCLUSION
    fact = ClaimClass.VERIFIED_FACT
    limitation = ClaimClass.LIMITATION
    iq_repository = iq.repository_summary
    q4_repository = q4.repository_summary
    architecture = iq.architecture_summary
    source_accounting = iq.source_accounting
    target_accounting = iq.target_accounting
    repository_comparison = comp.repository_comparison
    tensor_comparison = comp.tensor_identity_comparison
    shape_comparison = comp.shape_comparison
    routed_domain = next(
        item for item in iq.mapping_domain_summary if item["domain"] == "routed_experts"
    )
    transition_counts = Counter(
        {
            (baseline, candidate): sum(
                item.count
                for item in comp.type_transition_comparison.family_transitions
                if item.baseline_type == baseline and item.candidate_type == candidate
            )
            for baseline, candidate in (
                ("IQ1_S", "MXFP4"),
                ("IQ2_XXS", "MXFP4"),
                ("IQ3_XXS", "MXFP4"),
            )
        }
    )
    changed_transition_count = sum(transition_counts.values())
    resolved_revision = iq.repository_identity.resolved_revision
    payload_bytes_accepted = (
        iq_repository["tensor_payload_bytes_accepted"]
        + q4_repository["tensor_payload_bytes_accepted"]
    )
    payload_count_word = "zero" if payload_bytes_accepted == 0 else f"{payload_bytes_accepted:,}"
    if shape_comparison.normalized_shape_equal_count != tensor_comparison.matched_count:
        raise OmivInputError("matched identity and normalized-shape counts differ")
    claims = [
        _claim(
            1,
            "Immutable revision",
            f"The repository revision is pinned to {resolved_revision}.",
            fact,
            "repository_identity",
            artifacts,
            ["VALIDATE-001", "COMPARE-004"],
            [],
        ),
        _claim(
            2,
            "IQ1_M shard count",
            f"UD-IQ1_M contains {iq_repository['selected_shard_count']} selected "
            "GGUF shards at the pinned revision.",
            fact,
            "repository_layout",
            [iq_digest],
            ["VALIDATE-004"],
            [],
        ),
        _claim(
            3,
            "Q4 shard count",
            f"UD-Q4_K_XL contains {q4_repository['selected_shard_count']} selected "
            "GGUF shards at the same pinned revision.",
            fact,
            "repository_layout",
            [q4_digest],
            ["VALIDATE-004"],
            [],
        ),
        _claim(
            4,
            "IQ1_M repository bytes",
            "The selected UD-IQ1_M repository files total "
            f"{iq_repository['total_repository_bytes']:,} bytes.",
            fact,
            "repository_layout",
            [iq_digest],
            ["VALIDATE-004"],
            [],
        ),
        _claim(
            5,
            "Q4 repository bytes",
            "The selected UD-Q4_K_XL repository files total "
            f"{q4_repository['total_repository_bytes']:,} bytes.",
            fact,
            "repository_layout",
            [q4_digest],
            ["VALIDATE-004"],
            [],
        ),
        _claim(
            6,
            "Zero payload bytes",
            f"OMIV accepted {payload_count_word} tensor payload bytes while generating "
            "remote structural evidence.",
            fact,
            "range_semantics",
            [iq_digest, q4_digest],
            ["VALIDATE-005"],
            [],
        ),
        _claim(
            7,
            "Bounded complete headers",
            "Complete GGUF headers were parsed using bounded Range requests.",
            fact,
            "complete_header",
            [iq_digest, q4_digest],
            ["VALIDATE-006"],
            [],
        ),
        _claim(
            8,
            "Descriptor totals",
            f"Both variants contain {iq_repository['aggregated_tensor_count']:,} "
            "verified target tensor descriptors.",
            fact,
            "split_container",
            [iq_digest, q4_digest],
            ["VALIDATE-007"],
            [],
        ),
        _claim(
            9,
            "Bounded spans",
            "All tensor spans are computable, bounded, non-conflicting, and "
            "non-overlapping under their recorded type policies.",
            structural,
            "payload_span_bounds",
            [iq_digest, q4_digest],
            ["VALIDATE-007", "COMPARE-016"],
            [],
        ),
        _claim(
            10,
            "Kimi target ontology",
            "The target GGUF tensors satisfy the recorded Kimi K3 target ontology.",
            structural,
            "target_ontology",
            [iq_digest, q4_digest],
            ["VALIDATE-008"],
            [ontology],
        ),
        _claim(
            11,
            "Layer schedule",
            f"The verified architecture contains {architecture['layers']} layers, with "
            f"{architecture['kda_layers']} KDA and {architecture['mla_layers']} MLA layers.",
            fact,
            "target_ontology",
            [iq_digest, q4_digest],
            ["VALIDATE-008"],
            [ontology],
        ),
        _claim(
            12,
            "Dense and MoE schedule",
            f"Layer {architecture['dense_layers'][0]} is dense and layers "
            f"{architecture['moe_layer_range'][0]} through "
            f"{architecture['moe_layer_range'][1]} are MoE.",
            fact,
            "target_ontology",
            [iq_digest, q4_digest],
            ["VALIDATE-008"],
            [ontology],
        ),
        _claim(
            13,
            "Routed experts",
            f"The target structurally encodes {architecture['routed_experts']} routed "
            f"experts and {architecture['experts_used']} experts used.",
            structural,
            "target_ontology",
            [iq_digest, q4_digest],
            ["VALIDATE-008"],
            [ontology],
        ),
        _claim(
            14,
            "Shared experts",
            "Shared-expert structure is present across all "
            f"{architecture['moe_layer_range'][1] - architecture['moe_layer_range'][0] + 1} "
            "MoE layers.",
            structural,
            "structural_semantic_mapping",
            [iq_digest, q4_digest],
            ["VALIDATE-009"],
            [mapping],
        ),
        _claim(
            15,
            "Source inventory",
            "The source checkpoint inventory contains "
            f"{source_accounting['physical_records']:,} physical records.",
            fact,
            "structural_semantic_mapping",
            [iq_digest, q4_digest],
            ["VALIDATE-011"],
            [mapping],
        ),
        _claim(
            16,
            "Source accounting",
            f"All {source_accounting['accounted']:,} source records are explicitly "
            "accounted for under Phase 4F-5.",
            structural,
            "structural_semantic_mapping",
            [iq_digest, q4_digest],
            ["VALIDATE-011"],
            [mapping],
        ),
        _claim(
            17,
            "Target accounting",
            f"All {target_accounting['accounted']:,} target descriptors are "
            "explicitly accounted for.",
            structural,
            "structural_semantic_mapping",
            [iq_digest, q4_digest],
            ["VALIDATE-012"],
            [mapping],
        ),
        _claim(
            18,
            "Routed packing",
            f"{routed_domain['target_numerator']} complete routed-expert source groups "
            f"map structurally to {routed_domain['target_numerator']} packed target tensors.",
            structural,
            "structural_semantic_mapping",
            [iq_digest, q4_digest],
            ["VALIDATE-009"],
            [mapping],
        ),
        _claim(
            19,
            "Provenance unavailable",
            "Artifact-specific conversion provenance is unavailable.",
            limitation,
            "artifact_specific_provenance",
            artifacts,
            ["VALIDATE-014"],
            [],
        ),
        _claim(
            20,
            "Payload not checked",
            "Payload verification is not checked.",
            limitation,
            "payload_integrity",
            artifacts,
            ["VALIDATE-015", "COMPARE-018"],
            [],
        ),
        _claim(
            21,
            "Quantization not checked",
            "Quantization fidelity is not checked.",
            limitation,
            "quantization_fidelity",
            artifacts,
            ["VALIDATE-016", "COMPARE-019"],
            [],
        ),
        _claim(
            22,
            "Tokenizer not checked",
            "Tokenizer parity is not checked.",
            limitation,
            "tokenizer_parity",
            artifacts,
            ["VALIDATE-017"],
            [],
        ),
        _claim(
            23,
            "Runtime not checked",
            "Runtime parity is not checked.",
            limitation,
            "runtime_parity",
            artifacts,
            ["VALIDATE-018", "COMPARE-020"],
            [],
        ),
        _claim(
            24,
            "IQ1_M validation",
            "UD-IQ1_M is structurally validated with limitations.",
            structural,
            "deterministic_verification",
            [iq_digest],
            ["VALIDATE-020"],
            [],
        ),
        _claim(
            25,
            "Q4 validation",
            "UD-Q4_K_XL is structurally validated with limitations.",
            structural,
            "deterministic_verification",
            [q4_digest],
            ["VALIDATE-020"],
            [],
        ),
        _claim(
            26,
            "Cross-quantization result",
            "UD-IQ1_M and UD-Q4_K_XL are structurally equivalent with quantization "
            "differences under the recorded comparison policy.",
            structural,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-021"],
            [comparison_policy],
        ),
        _claim(
            27,
            "Identity and shape equivalence",
            "The two variants contain the same "
            f"{tensor_comparison.matched_count:,} normalized tensor identities and shapes.",
            structural,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-006", "COMPARE-007"],
            [comparison_policy],
        ),
        _claim(
            28,
            "Transition scope",
            "The only observed GGML family transitions occur in "
            f"{changed_transition_count} packed routed-expert targets.",
            structural,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-010", "COMPARE-011"],
            [comparison_policy],
        ),
        _claim(
            29,
            "Directional transitions",
            "The directional transitions are IQ1_S to MXFP4: "
            f"{transition_counts[('IQ1_S', 'MXFP4')]}, IQ2_XXS to MXFP4: "
            f"{transition_counts[('IQ2_XXS', 'MXFP4')]}, and IQ3_XXS to MXFP4: "
            f"{transition_counts[('IQ3_XXS', 'MXFP4')]}.",
            fact,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-010"],
            [comparison_policy],
        ),
        _claim(
            30,
            "MXFP4 scope",
            "MXFP4 is structurally allowed only for packed routed-expert gate, up, "
            "and down families under the recorded policy.",
            structural,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-011"],
            [comparison_policy],
        ),
        _claim(
            31,
            "Repository storage ratio",
            "The Q4 repository-file byte total is approximately "
            f"{repository_comparison.deterministic_decimal[:5]} times the IQ1_M total.",
            fact,
            "cross_quantization_structural_comparison",
            [comp_digest],
            ["COMPARE-016"],
            [comparison_policy],
            limitation="This is a physical storage ratio, not a quality measurement.",
        ),
        _claim(
            32,
            "Storage is not quality",
            "The physical size ratio is not evidence of numerical quality.",
            limitation,
            "quantization_fidelity",
            [comp_digest],
            ["COMPARE-019"],
            [comparison_policy],
        ),
    ]
    forbidden = [
        "The weights are correct.",
        "The conversion is numerically correct.",
        "The published artifact was generated by the pinned converter revision.",
        "The expert packing order is correct.",
        "The scale records are numerically associated correctly.",
        "MXFP4 is more accurate.",
        "Q4 is better than IQ1_M.",
        "IQ1_M is worse than Q4.",
        "The quantization preserves model quality.",
        "The tokenizer is equivalent.",
        "The logits are equivalent.",
        "Runtime outputs are equivalent.",
        "The model is production certified.",
        "The artifact is fully verified.",
        "The model payload is intact.",
        "The validation proves benchmark performance.",
        "The validation proves safety.",
        "The validation proves multimodal behavior.",
        (
            "The validation proves the full Kimi K3 release, beyond the selected "
            "text GGUF artifact set."
        ),
    ]
    validate_claim_support(
        claims,
        artifact_digests={iq_digest, q4_digest, comp_digest},
        finding_ids={
            *(item.finding_id for item in iq.findings),
            *(item.finding_id for item in q4.findings),
            *(item.finding_id for item in comp.findings),
        },
        policy_digests={
            ontology,
            mapping,
            comparison_policy,
            comp.profile_policy.policy_digest,
            iq.profile_policy.policy_digest,
            iq.model_pack_identity.digest,
        },
    )
    draft = PublicClaimRegistry(
        claims=claims,
        globally_forbidden_wording=forbidden,
        registry_digest="0" * 64,
    )
    return draft.model_copy(update={"registry_digest": _digest_model(draft, "registry_digest")})


def build_reproducibility_manifest(root: Path) -> ArticleReproducibilityManifest:
    iq, q4, comp = _verified(root)
    commands = [
        ReproductionCommand(
            order=1,
            phase="online_evidence_generation",
            command=(
                "omiv remote-snapshot --provider huggingface "
                "--repo unsloth/Kimi-K3-GGUF "
                f"--revision {REVISION} --path-prefix UD-IQ1_M "
                '--pattern "*.gguf" '
                "--output reproductions/UD-IQ1_M.snapshot.json "
                "--report-output reproductions/UD-IQ1_M.snapshot.report.json "
                "--markdown-output reproductions/UD-IQ1_M.snapshot.report.md"
            ),
            network_required=True,
            expected_exit_code=0,
            expected_status="PASS",
        ),
        ReproductionCommand(
            order=2,
            phase="online_evidence_generation",
            command=(
                "omiv remote-snapshot --provider huggingface "
                "--repo unsloth/Kimi-K3-GGUF "
                f"--revision {REVISION} --path-prefix UD-Q4_K_XL "
                '--pattern "*.gguf" '
                "--output reproductions/UD-Q4_K_XL.snapshot.json "
                "--report-output reproductions/UD-Q4_K_XL.snapshot.report.json "
                "--markdown-output reproductions/UD-Q4_K_XL.snapshot.report.md"
            ),
            network_required=True,
            expected_exit_code=0,
            expected_status="PASS",
        ),
        ReproductionCommand(
            order=3,
            phase="offline",
            command=f"omiv independent-validation-inventory-verify --input {IQ_VALIDATION}",
            network_required=False,
            expected_exit_code=0,
            expected_status="PASS",
        ),
        ReproductionCommand(
            order=4,
            phase="offline",
            command=f"omiv independent-validation-inventory-verify --input {Q4_VALIDATION}",
            network_required=False,
            expected_exit_code=0,
            expected_status="PASS",
        ),
        ReproductionCommand(
            order=5,
            phase="offline",
            command=f"omiv structural-comparison-inventory-verify --input {COMPARISON}",
            network_required=False,
            expected_exit_code=0,
            expected_status="PASS",
        ),
        ReproductionCommand(
            order=6,
            phase="offline",
            command=(
                "omiv article-preflight --root . --article "
                "articles/validating-kimi-k3-gguf-with-omiv.md"
            ),
            network_required=False,
            expected_exit_code=0,
            expected_status="PASS",
        ),
    ]
    expected = {
        IQ_VALIDATION: iq.inventory_digest,
        Q4_VALIDATION: q4.inventory_digest,
        COMPARISON: comp.comparison_digest,
    }
    draft = ArticleReproducibilityManifest(
        repository="unsloth/Kimi-K3-GGUF",
        resolved_revision=REVISION,
        omiv_repository_commit=BASELINE_COMMIT,
        required_software_assumptions=[
            "Python version supported by the checked-in OMIV project",
            "OMIV dependencies installed from the pinned project metadata",
            "Canonical Phase 4F-1 through 4F-7 artifacts present",
        ],
        commands=commands,
        expected_artifact_paths=sorted(expected),
        expected_digests=expected,
        expected_remote_header_bytes={"UD-IQ1_M": 7098363, "UD-Q4_K_XL": 7100165},
        expected_tensor_payload_bytes_accepted=0,
        known_provider_limitations=[
            "Original snapshot and Range evidence generation requires approved HTTPS access.",
            "Publication-package verification is entirely offline.",
        ],
        reproducibility_digest="0" * 64,
    )
    return draft.model_copy(
        update={"reproducibility_digest": _digest_model(draft, "reproducibility_digest")}
    )


def _report_envelope(root: Path, relative: str) -> str:
    document = json.loads((root / relative).read_text(encoding="utf-8"))
    digest = document.get("integrity", {}).get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise OmivInputError(f"missing report envelope digest: {relative}")
    return digest


def _canonical_artifacts(root: Path, iq: Any, q4: Any, comp: Any) -> list[ArticleArtifact]:
    by_path: dict[str, ArticleArtifact] = {}
    for variant, validation in (("iq1_m", iq), ("q4", q4)):
        for entry in validation.artifact_index.entries:
            artifact = ArticleArtifact(
                role=f"{variant}:{entry.role}",
                schema_id=entry.schema_id,
                relative_path=entry.relative_path,
                canonical_digest=entry.canonical_digest,
                size_bytes=entry.size_bytes,
                required=entry.required,
                producer_phase=entry.producer_phase,
                verification_command=entry.verification_command,
            )
            by_path.setdefault(artifact.relative_path, artifact)
    for entry in comp.artifact_index:
        by_path.setdefault(
            entry.relative_path,
            ArticleArtifact(
                role=f"comparison:{entry.role}",
                schema_id=entry.schema_id,
                relative_path=entry.relative_path,
                canonical_digest=entry.digest,
                size_bytes=entry.size_bytes,
                required=entry.required,
                producer_phase="4F-7",
                verification_command=entry.verification_command,
            ),
        )
    extras = [
        (
            IQ_VALIDATION,
            "iq1_m:validation",
            "omiv.independent-model-validation.v1",
            iq.inventory_digest,
        ),
        (
            Q4_VALIDATION,
            "q4:validation",
            "omiv.independent-model-validation.v1",
            q4.inventory_digest,
        ),
        (COMPARISON, "comparison:inventory", comp.schema_id, comp.comparison_digest),
    ]
    for relative, role, schema, digest in extras:
        path = root / relative
        by_path[relative] = ArticleArtifact(
            role=role,
            schema_id=schema,
            relative_path=relative,
            canonical_digest=digest,
            size_bytes=path.stat().st_size,
            required=True,
            producer_phase="4F-6" if "validation" in role else "4F-7",
            verification_command=(
                f"omiv independent-validation-inventory-verify --input {relative}"
                if "validation" in role
                else f"omiv structural-comparison-inventory-verify --input {relative}"
            ),
        )
    report_specs = [
        (
            IQ_REPORT,
            "iq1_m:validation_report",
            "omiv.independent-model-validation-report.v1",
            "4F-6",
        ),
        (
            Q4_REPORT,
            "q4:validation_report",
            "omiv.independent-model-validation-report.v1",
            "4F-7",
        ),
        (
            COMPARISON_REPORT,
            "comparison:report",
            "omiv.model-artifact-structural-comparison-report.v1",
            "4F-7",
        ),
    ]
    for relative, role, schema, phase in report_specs:
        path = root / relative
        by_path[relative] = ArticleArtifact(
            role=role,
            schema_id=schema,
            relative_path=relative,
            canonical_digest=_report_envelope(root, relative),
            size_bytes=path.stat().st_size,
            required=True,
            producer_phase=phase,
            verification_command=f"omiv report-verify --input {relative}",
        )
    return [by_path[key] for key in sorted(by_path)]


def build_evidence_manifest(
    root: Path,
    claims: PublicClaimRegistry,
    reproduction: ArticleReproducibilityManifest,
) -> ArticleEvidenceManifest:
    iq, q4, comp = _verified(root)
    stage_status = {item.stage.value: item.status.value for item in iq.evidence_stages}
    draft = ArticleEvidenceManifest(
        subject="Kimi K3 UD-IQ1_M and UD-Q4_K_XL split GGUF artifacts",
        repository=iq.repository_identity.repository,
        resolved_revision=iq.repository_identity.resolved_revision,
        baseline_commit=BASELINE_COMMIT,
        model_pack_identity=iq.model_pack_identity.model_dump(mode="json"),
        converter_evidence_identity={
            "project": "llama.cpp",
            "revision": CONVERTER_REVISION,
            "role": "converter-rule and MXFP4 structural evidence",
        },
        canonical_artifacts=_canonical_artifacts(root, iq, q4, comp),
        report_envelope_digests={
            "UD-IQ1_M": _report_envelope(root, IQ_REPORT),
            "UD-Q4_K_XL": _report_envelope(root, Q4_REPORT),
            "comparison": _report_envelope(root, COMPARISON_REPORT),
        },
        evidence_graph_digests={
            "UD-IQ1_M": iq.evidence_graph_digest,
            "UD-Q4_K_XL": q4.evidence_graph_digest,
        },
        policy_digests={
            "model_pack": iq.model_pack_identity.digest,
            "ontology": iq.model_pack_identity.ontology_policy_digest,
            "mapping": iq.model_pack_identity.mapping_policy_digest,
            "comparison": comp.policy.policy_digest,
            "comparison_profiles": comp.profile_policy.policy_digest,
            "validation_profiles": iq.profile_policy.policy_digest,
        },
        claim_registry_digest=claims.registry_digest,
        reproducibility_manifest_digest=reproduction.reproducibility_digest,
        supported_evidence_stages=sorted(
            key for key, value in stage_status.items() if value in {"PASS", "AVAILABLE"}
        ),
        unavailable_evidence_stages=sorted(
            key for key, value in stage_status.items() if value == "UNAVAILABLE"
        ),
        not_checked_evidence_stages=sorted(
            key for key, value in stage_status.items() if value == "NOT_CHECKED"
        ),
        manifest_digest="0" * 64,
    )
    return draft.model_copy(update={"manifest_digest": _digest_model(draft, "manifest_digest")})


def build_article_index(
    root: Path,
    manifest: ArticleEvidenceManifest,
    claims: PublicClaimRegistry,
    reproduction: ArticleReproducibilityManifest,
) -> ArticleArtifactIndex:
    specs = [
        ("article", "markdown", "articles/validating-kimi-k3-gguf-with-omiv.md"),
        ("community_notes", "markdown", "articles/kimi-k3-gguf-community-release.md"),
        ("social_hn", "markdown", "articles/social/kimi-k3-gguf-hn-draft.md"),
        ("social_linkedin", "markdown", "articles/social/kimi-k3-gguf-linkedin-draft.md"),
        ("social_x", "markdown", "articles/social/kimi-k3-gguf-x-draft.md"),
        ("claim_registry", claims.schema_id, CLAIM_PATH),
        ("evidence_manifest", manifest.schema_id, MANIFEST_PATH),
        ("reproducibility", reproduction.schema_id, REPRO_PATH),
    ]
    entries = [
        ArticleIndexEntry(
            role=role,
            schema_id=schema,
            relative_path=relative,
            digest=_raw_digest(root / relative),
            size_bytes=(root / relative).stat().st_size,
            required=True,
            verification_command=(
                "omiv article-preflight --root . --article "
                "articles/validating-kimi-k3-gguf-with-omiv.md"
            ),
        )
        for role, schema, relative in specs
    ]
    entries.extend(
        ArticleIndexEntry(
            role=f"evidence:{item.role}",
            schema_id=item.schema_id,
            relative_path=item.relative_path,
            digest=item.canonical_digest,
            size_bytes=item.size_bytes,
            required=item.required,
            verification_command=item.verification_command,
        )
        for item in manifest.canonical_artifacts
    )
    entries.sort(key=lambda item: item.relative_path)
    draft = ArticleArtifactIndex(entries=entries, index_digest="0" * 64)
    return draft.model_copy(update={"index_digest": _digest_model(draft, "index_digest")})


def build_article_package(
    root: Path,
) -> tuple[
    PublicClaimRegistry,
    ArticleReproducibilityManifest,
    ArticleEvidenceManifest,
]:
    root = root.resolve()
    claims = build_claim_registry(root)
    reproduction = build_reproducibility_manifest(root)
    manifest = build_evidence_manifest(root, claims, reproduction)
    return claims, reproduction, manifest


def claim_class_counts(registry: PublicClaimRegistry) -> dict[str, int]:
    return dict(sorted(Counter(item.claim_class.value for item in registry.claims).items()))


def build_publication_numeric_facts(root: Path) -> tuple[str, ...]:
    """Reconstruct the publication's major numeric facts from canonical evidence."""
    iq, q4, comparison = _verified(root)
    iq_repository = iq.repository_summary
    q4_repository = q4.repository_summary
    source_states = iq.source_accounting["states"]
    target_states = iq.target_accounting["states"]
    repository_ratio = comparison.repository_comparison
    encoded_ratio = comparison.encoded_span_comparison
    with localcontext() as context:
        context.prec = 40
        encoded_decimal = format(
            Decimal(encoded_ratio.ratio_numerator) / Decimal(encoded_ratio.ratio_denominator),
            ".12f",
        )
    values = {
        f"{iq_repository['total_repository_bytes']:,}",
        f"{q4_repository['total_repository_bytes']:,}",
        f"{iq_repository['aggregated_tensor_count']:,}",
        f"{iq.source_accounting['physical_records']:,}",
        f"{iq_repository['target_type_counts']['F32']:,}",
        f"{iq_repository['target_type_counts']['Q8_0']:,}",
        f"{source_states['directly_mapped']:,}",
        f"{source_states['packed_group_member']:,}",
        f"{target_states['packed_group_target']:,}",
        f"{repository_ratio.ratio_numerator_reduced}",
        f"{repository_ratio.ratio_denominator_reduced}",
        repository_ratio.deterministic_decimal,
        f"{encoded_ratio.baseline_total_encoded_bytes:,}",
        f"{encoded_ratio.candidate_total_encoded_bytes:,}",
        f"{encoded_ratio.ratio_numerator}",
        f"{encoded_ratio.ratio_denominator}",
        encoded_decimal,
    }
    return tuple(sorted(values))
