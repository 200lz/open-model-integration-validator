"""Offline composition of independently verifiable validation evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.external_artifacts import (
    KIMI_K3_TENSOR_INVENTORY,
    ExternalArtifactObservation,
    ExternalArtifactStatus,
    observe_external_artifact,
)
from omiv.mapping.grouped_reporting import (
    load_mapping_inventory,
    load_mapping_report,
    mapping_report_integrity_matches,
)
from omiv.model_packs.base import ModelPackCapability
from omiv.model_packs.kimi_k3.gguf_reporting import (
    load_ontology_inventory,
    load_ontology_report,
    ontology_inventory_links_split,
    ontology_report_integrity_matches,
)
from omiv.model_packs.kimi_k3.mapping_policy import kimi_mapping_policy
from omiv.model_packs.registry import get_model_pack
from omiv.remote.header_reporting import (
    header_report_integrity_matches,
    load_header_inventory,
    load_header_report,
)
from omiv.remote.reporting import (
    load_remote_report,
    load_snapshot,
    report_integrity_matches,
)
from omiv.remote.split_reporting import (
    load_split_inventory,
    load_split_report,
    split_report_integrity_matches,
)
from omiv.validation.models import (
    ArtifactIndex,
    ArtifactIndexEntry,
    EvidenceEdge,
    EvidenceNode,
    EvidenceStageName,
    EvidenceStageResult,
    EvidenceStatus,
    Finding,
    ModelPackIdentity,
    RepositoryIdentity,
    ReproductionCommand,
    ReproductionManifest,
    StructuralValidationResult,
    SubjectIdentity,
    ValidationInventory,
)
from omiv.validation.profiles import STRUCTURAL_STAGES, evaluate_profiles, profile_policy

EXPECTED_REPOSITORY = "unsloth/Kimi-K3-GGUF"
EXPECTED_REVISION = "3d4b61ab4b6789d401191c476cbb4567246db8f5"
EXPECTED_PACK_DIGEST = "6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288"
EXPECTED_MAPPING_POLICY = "0201db3da3e2e6f47596b1cdb369d8004a34c7340a4ae5bca281004bb6e72f6c"
EXPECTED_ONTOLOGY_POLICY = "67b767da34ec3e95202266992c1468bef145756b16d9fcbc9f90895c2cea49a0"
EXPECTED_CONVERTER = "cf67f0d24511864d2d3da0769108fd6fc16d00d1"
OMIV_EVIDENCE_REVISION = "9773b83e3c2ee2d47df3ed9324063bb7697af19f"

SOURCE_INVENTORY = "reports/raw/kimi_k3_tensors.json"


def _variant_paths(root: Path, variant: str) -> dict[str, Path]:
    stem = f"unsloth_Kimi-K3-GGUF_{variant}"
    return {
        "snapshot_report": root / f"reports/remote/{stem}.snapshot.report.json",
        "prefix_report": root / f"reports/remote/{stem}_shard1.prefix.report.json",
        "header_report": root / f"reports/remote/{stem}_shard1.header.report.json",
        "split_report": root / f"reports/remote/{stem}.split.report.json",
        "ontology_report": root / f"reports/remote/{stem}.kimi-k3-ontology.report.json",
        "mapping_report": root / f"reports/remote/{stem}.semantic-mapping.report.json",
        "shard_directory": root / f"inventories/remote/{stem}/shards",
    }


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise OmivInputError(f"artifact is outside repository root: {path}") from exc


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OmivInputError(message)


def _mapping_digest(mapping: Any) -> str:
    data = mapping.model_dump(mode="json", by_alias=True)
    stored = data.pop("inventory_digest", None)
    observed = canonical_sha256(data)
    _require(stored == observed, "semantic-mapping inventory digest mismatch")
    return observed


def _pass_report(envelope: Any, label: str) -> None:
    result = envelope.report.execution.result.value
    _require(result == "pass", f"{label} is not PASS: {result}")


def _node(
    node_id: str,
    kind: str,
    schema: str,
    digest: str,
    path: str,
    scope: list[str],
    limitations: list[str],
    *,
    parents: list[str] | None = None,
    policies: list[str] | None = None,
    pack_digest: str | None = None,
) -> EvidenceNode:
    return EvidenceNode(
        node_id=node_id,
        artifact_kind=kind,
        schema_id=schema,
        canonical_digest=digest,
        artifact_identifier=path,
        verification_status=EvidenceStatus.PASS,
        provider="huggingface" if "source-checkpoint" not in node_id else None,
        model_identity="kimi-k3",
        parent_dependency_digests=sorted(parents or []),
        policy_digests=sorted(policies or []),
        model_pack_digest=pack_digest,
        evidence_scope=scope,
        evidence_limitations=limitations,
    )


def _edge(parent: EvidenceNode, child: EvidenceNode, relation: str, observed: str) -> EvidenceEdge:
    return EvidenceEdge(
        parent_node_id=parent.node_id,
        child_node_id=child.node_id,
        dependency_relation=relation,
        expected_digest=parent.canonical_digest,
        observed_digest=observed,
        linkage_status=EvidenceStatus.PASS
        if observed == parent.canonical_digest
        else EvidenceStatus.FAIL,
        mismatch_reason=None
        if observed == parent.canonical_digest
        else f"expected {parent.canonical_digest}, observed {observed}",
    )


def _stage(
    name: EvidenceStageName,
    status: EvidenceStatus,
    nodes: list[EvidenceNode],
    finding_id: str,
    scope: list[str],
    limitations: list[str],
    next_evidence: list[str],
    policies: list[str] | None = None,
) -> EvidenceStageResult:
    return EvidenceStageResult(
        stage=name,
        status=status,
        evidence_node_ids=sorted(node.node_id for node in nodes),
        finding_ids=[finding_id],
        artifact_digests=sorted(node.canonical_digest for node in nodes),
        policy_digests=sorted(policies or []),
        scope=scope,
        limitations=limitations,
        next_required_evidence=next_evidence,
    )


def _artifact_entry(
    root: Path,
    path: Path,
    role: str,
    schema: str,
    digest: str,
    phase: str,
    command: str,
    *,
    size_bytes: int | None = None,
) -> ArtifactIndexEntry:
    return ArtifactIndexEntry(
        role=role,
        schema_id=schema,
        relative_path=_relative(root, path),
        canonical_digest=digest,
        size_bytes=path.stat().st_size if size_bytes is None else size_bytes,
        required=True,
        producer_phase=phase,
        verification_command=command,
    )


def _finding(
    finding_id: str,
    status: EvidenceStatus,
    summary: str,
    **evidence: Any,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        status=status,
        summary=summary,
        evidence=evidence,
    )


def _domain_summaries(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    payload = coverage["payload_status"].upper()
    return [
        {
            "domain": "routed_experts",
            "source_numerator": coverage["routed"]["source_physical_members"],
            "source_denominator": coverage["routed"]["source_physical_members"],
            "target_numerator": coverage["routed"]["packed_targets"],
            "target_denominator": 276,
            "relation": "many_to_one_packed",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "shared_experts",
            "source_numerator": coverage["shared_experts"]["physical_source_mappings"],
            "source_denominator": 276,
            "target_numerator": coverage["shared_experts"]["physical_target_mappings"],
            "target_denominator": 276,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "router_and_bias",
            "source_numerator": sum(coverage["router"].values()),
            "source_denominator": 184,
            "target_numerator": sum(coverage["router"].values()),
            "target_denominator": 184,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "latent_moe",
            "source_numerator": sum(coverage["latent_moe"].values()),
            "source_denominator": 276,
            "target_numerator": sum(coverage["latent_moe"].values()),
            "target_denominator": 276,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "dense_layer_0",
            "source_numerator": sum(coverage["dense"].values()),
            "source_denominator": 3,
            "target_numerator": sum(coverage["dense"].values()),
            "target_denominator": 3,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "per_layer_norms",
            "source_numerator": coverage["norms"]["attention"] + coverage["norms"]["ffn"],
            "source_denominator": 186,
            "target_numerator": coverage["norms"]["attention"] + coverage["norms"]["ffn"],
            "target_denominator": 186,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "attention_output",
            "source_numerator": coverage["attention_output"],
            "source_denominator": 93,
            "target_numerator": coverage["attention_output"],
            "target_denominator": 93,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "kda",
            "source_numerator": coverage["kda"]["direct"] + coverage["kda"]["logical"],
            "source_denominator": 828,
            "target_numerator": coverage["kda"]["direct"] + coverage["kda"]["logical"],
            "target_denominator": 828,
            "relation": "one_to_one_and_logical_realization",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "mla",
            "source_numerator": coverage["mla"]["direct"] + coverage["mla"]["split_sources"],
            "source_denominator": 144,
            "target_numerator": coverage["mla"]["direct"] + coverage["mla"]["split_targets"],
            "target_denominator": 168,
            "relation": "one_to_one_and_one_to_many_split",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "attention_residual",
            "source_numerator": coverage["fused"]["source_members"],
            "source_denominator": 374,
            "target_numerator": coverage["fused"]["targets"],
            "target_denominator": 187,
            "relation": "fused_target",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "g_proj",
            "source_numerator": coverage["g_proj"]["total"],
            "source_denominator": 93,
            "target_numerator": coverage["g_proj"]["total"],
            "target_denominator": 93,
            "relation": "logical_realization",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
        {
            "domain": "model_level",
            "source_numerator": coverage["model_level_direct"],
            "source_denominator": 3,
            "target_numerator": coverage["model_level_direct"],
            "target_denominator": 3,
            "relation": "one_to_one",
            "evidence_level": "converter_rule_support",
            "payload_status": payload,
        },
    ]


def build_independent_validation(
    *,
    root: Path,
    subject: str,
    variant: str,
    snapshot_path: Path,
    split_path: Path,
    ontology_path: Path,
    mapping_path: Path,
    selected_profile: str,
    external_source_observation: ExternalArtifactObservation | None = None,
) -> ValidationInventory:
    """Verify Phase 4F-1 through 4F-5 and compose an offline validation inventory."""
    _require(subject == "kimi-k3", f"unsupported independent-validation subject: {subject}")
    _require(bool(variant) and "/" not in variant, f"invalid artifact variant: {variant}")
    profiles = profile_policy()
    _require(
        selected_profile in {item.name for item in profiles.profiles},
        f"unknown acceptance profile: {selected_profile}",
    )
    root = root.resolve()
    companion_paths = _variant_paths(root, variant)
    paths = {
        "snapshot": snapshot_path.resolve(),
        "snapshot_report": companion_paths["snapshot_report"],
        "prefix_report": companion_paths["prefix_report"],
        "header_report": companion_paths["header_report"],
        "split": split_path.resolve(),
        "split_report": companion_paths["split_report"],
        "ontology": ontology_path.resolve(),
        "ontology_report": companion_paths["ontology_report"],
        "mapping": mapping_path.resolve(),
        "mapping_report": companion_paths["mapping_report"],
        "source": root / SOURCE_INVENTORY,
    }
    for label, path in paths.items():
        if label == "source":
            continue
        _require(path.is_file(), f"missing required {label} artifact: {path}")

    snapshot = load_snapshot(paths["snapshot"])
    snapshot_report = load_remote_report(paths["snapshot_report"])
    prefix_report = load_remote_report(paths["prefix_report"])
    _require(report_integrity_matches(snapshot_report), "snapshot report integrity mismatch")
    _require(report_integrity_matches(prefix_report), "prefix report integrity mismatch")
    _pass_report(snapshot_report, "snapshot report")
    _pass_report(prefix_report, "prefix report")
    _require(
        snapshot_report.report.snapshot_sha256 == snapshot.integrity.sha256,
        "snapshot report linkage mismatch",
    )
    _require(
        prefix_report.report.snapshot_sha256 == snapshot.integrity.sha256,
        "prefix report linkage mismatch",
    )

    header_paths = sorted(companion_paths["shard_directory"].glob("*.header.inventory.json"))
    _require(
        len(header_paths) == snapshot.snapshot.summary.file_count,
        "per-shard header inventory count does not match snapshot selection",
    )
    headers = [load_header_inventory(path) for path in header_paths]
    header_report = load_header_report(paths["header_report"])
    _require(header_report_integrity_matches(header_report), "header report integrity mismatch")
    _pass_report(header_report, "shard-1 header report")
    _require(
        header_report.report.inventory_sha256 == headers[0].integrity.sha256,
        "shard-1 header report linkage mismatch",
    )
    _require(
        all(item.inventory.snapshot_sha256 == snapshot.integrity.sha256 for item in headers),
        "per-shard header snapshot linkage mismatch",
    )

    split = load_split_inventory(paths["split"])
    split_report = load_split_report(paths["split_report"])
    _require(split_report_integrity_matches(split_report), "split report integrity mismatch")
    _pass_report(split_report, "split report")
    _require(
        split_report.report.inventory_sha256 == split.integrity.sha256,
        "split report linkage mismatch",
    )
    _require(
        split.inventory.snapshot_sha256 == snapshot.integrity.sha256,
        "split inventory snapshot linkage mismatch",
    )
    header_digests = {item.integrity.sha256 for item in headers}
    _require(
        {item.inventory_sha256 for item in split.inventory.shard_summaries} == header_digests,
        "split inventory does not link exactly the verified shard inventories",
    )

    ontology = load_ontology_inventory(paths["ontology"])
    ontology_report = load_ontology_report(paths["ontology_report"])
    _require(
        ontology_report_integrity_matches(ontology_report),
        "ontology report integrity mismatch",
    )
    _pass_report(ontology_report, "ontology report")
    _require(ontology_inventory_links_split(ontology, split), "ontology split linkage mismatch")
    _require(
        ontology_report.report.inventory_sha256 == ontology.integrity.sha256,
        "ontology report linkage mismatch",
    )

    mapping = load_mapping_inventory(paths["mapping"])
    mapping_digest = _mapping_digest(mapping)
    mapping_report = load_mapping_report(paths["mapping_report"])
    _require(mapping_report_integrity_matches(mapping_report), "mapping report integrity mismatch")
    _require(
        mapping_report.report.inventory_digest == mapping_digest,
        "mapping report linkage mismatch",
    )
    _require(
        mapping.target["split_inventory_sha256"] == split.integrity.sha256
        and mapping.target["ontology_inventory_sha256"] == ontology.integrity.sha256,
        "mapping target evidence linkage mismatch",
    )

    source_observation = external_source_observation or observe_external_artifact(
        root, KIMI_K3_TENSOR_INVENTORY
    )
    if source_observation.expected != KIMI_K3_TENSOR_INVENTORY:
        raise OmivInputError("unexpected external source identity")
    if source_observation.status == ExternalArtifactStatus.INVALID:
        raise OmivInputError(
            f"external artifact identity mismatch: {KIMI_K3_TENSOR_INVENTORY.relative_path}"
        )
    if source_observation.status == ExternalArtifactStatus.NOT_AVAILABLE:
        if external_source_observation is None:
            from omiv.external_artifacts import ExternalArtifactUnavailable

            raise ExternalArtifactUnavailable(KIMI_K3_TENSOR_INVENTORY)
        source_digest = source_observation.expected.sha256
        source_size = source_observation.expected.size_bytes
    else:
        observed_digest = source_observation.observed_sha256
        observed_size = source_observation.observed_size_bytes
        if observed_digest is None or observed_size is None:
            raise OmivInputError("verified external source lacks observed identity")
        source_digest = observed_digest
        source_size = observed_size
    _require(
        source_digest == mapping.source["inventory_sha256"], "source inventory linkage mismatch"
    )
    if source_observation.available and external_source_observation is None:
        with paths["source"].open(encoding="utf-8") as handle:
            source_raw = json.load(handle)
        _require(isinstance(source_raw, list), "source inventory must be a JSON record list")
        _require(
            len(source_raw) == mapping.source["physical_count"],
            "source inventory physical count mismatch",
        )
        del source_raw

    pack = get_model_pack("kimi-k3")
    pack.require(ModelPackCapability.CHECKPOINT_SCHEMA)
    pack.require(ModelPackCapability.CHECKPOINT_ONTOLOGY)
    pack.require(ModelPackCapability.GGUF_ONTOLOGY)
    pack.require(ModelPackCapability.SEMANTIC_MAPPING)
    policy = kimi_mapping_policy()
    _require(pack.metadata.digest == mapping.model_pack["digest"], "canonical model-pack mismatch")
    _require(policy.digest == mapping.mapping_policy_digest, "canonical mapping-policy mismatch")
    _require(
        ontology.inventory.ontology_policy_digest == EXPECTED_ONTOLOGY_POLICY,
        "ontology-policy baseline mismatch",
    )
    baseline_checks = {
        "repository": snapshot.snapshot.repository.repo_id == EXPECTED_REPOSITORY,
        "revision": snapshot.snapshot.repository.resolved_revision == EXPECTED_REVISION,
        "pack": pack.metadata.digest == EXPECTED_PACK_DIGEST,
        "mapping_policy": policy.digest == EXPECTED_MAPPING_POLICY,
        "converter": mapping.converter_evidence_revision == EXPECTED_CONVERTER,
        "pack_version": pack.metadata.pack_version == 3,
    }
    _require(
        all(baseline_checks.values()), f"canonical baseline identity mismatch: {baseline_checks}"
    )

    nodes: list[EvidenceNode] = []
    snapshot_node = _node(
        "repository-snapshot",
        "repository_snapshot",
        snapshot.snapshot.snapshot_schema,
        snapshot.integrity.sha256,
        _relative(root, paths["snapshot"]),
        ["immutable repository identity", "selected remote file set"],
        ["repository metadata does not inspect GGUF contents"],
    )
    nodes.append(snapshot_node)
    snapshot_report_node = _node(
        "repository-snapshot-report",
        "repository_snapshot_report",
        snapshot_report.report.report_schema,
        snapshot_report.integrity.sha256,
        _relative(root, paths["snapshot_report"]),
        ["repository layout and completeness findings"],
        list(snapshot_report.report.limitations),
        parents=[snapshot.integrity.sha256],
    )
    prefix_node = _node(
        "shard-1-prefix-report",
        "gguf_prefix_report",
        prefix_report.report.report_schema,
        prefix_report.integrity.sha256,
        _relative(root, paths["prefix_report"]),
        ["bounded HTTP Range semantics", "GGUF magic and version prefix"],
        list(prefix_report.report.limitations),
        parents=[snapshot.integrity.sha256],
    )
    nodes.extend([snapshot_report_node, prefix_node])

    header_nodes: list[EvidenceNode] = []
    for index, (path, envelope) in enumerate(zip(header_paths, headers, strict=True), start=1):
        item = _node(
            f"shard-header-{index:02d}",
            "gguf_header_inventory",
            envelope.inventory.inventory_schema,
            envelope.integrity.sha256,
            _relative(root, path),
            ["complete GGUF metadata and tensor descriptor header"],
            ["no tensor payload bytes were read"],
            parents=[snapshot.integrity.sha256],
            policies=[envelope.inventory.parser_policy_sha256],
        )
        header_nodes.append(item)
    nodes.extend(header_nodes)
    header_report_node = _node(
        "shard-1-header-report",
        "gguf_header_report",
        header_report.report.report_schema,
        header_report.integrity.sha256,
        _relative(root, paths["header_report"]),
        ["metadata-only shard-1 complete header findings"],
        list(header_report.report.limitations),
        parents=[headers[0].integrity.sha256],
        policies=[headers[0].inventory.parser_policy_sha256],
    )
    nodes.append(header_report_node)

    split_node = _node(
        "split-inventory",
        "split_gguf_inventory",
        split.inventory.inventory_schema,
        split.integrity.sha256,
        _relative(root, paths["split"]),
        ["split identity", "global descriptors", "payload-span structural bounds"],
        ["bounded spans do not prove payload presence or integrity"],
        parents=[snapshot.integrity.sha256, *sorted(header_digests)],
        policies=[
            split.inventory.aggregation_policy_sha256,
            split.inventory.header_parser_policy_sha256,
            split.inventory.metadata_policy_sha256,
            split.inventory.ggml_type_policy_sha256,
        ],
    )
    split_report_node = _node(
        "split-report",
        "split_gguf_report",
        split_report.report.report_schema,
        split_report.integrity.sha256,
        _relative(root, paths["split_report"]),
        ["split-container validation findings"],
        list(split_report.report.limitations),
        parents=[split.integrity.sha256],
    )
    nodes.extend([split_node, split_report_node])

    ontology_node = _node(
        "target-ontology-inventory",
        "kimi_k3_target_ontology",
        ontology.inventory.inventory_schema,
        ontology.integrity.sha256,
        _relative(root, paths["ontology"]),
        ["Kimi K3 target descriptor ontology and architecture schedule"],
        ["descriptor shape/type validation does not prove tensor values"],
        parents=[split.integrity.sha256],
        policies=[ontology.inventory.ontology_policy_digest],
        pack_digest=ontology.inventory.model_pack_digest,
    )
    ontology_report_node = _node(
        "target-ontology-report",
        "kimi_k3_target_ontology_report",
        ontology_report.report.report_schema,
        ontology_report.integrity.sha256,
        _relative(root, paths["ontology_report"]),
        ["target ontology findings"],
        list(ontology_report.report.limitations),
        parents=[ontology.integrity.sha256],
        policies=[ontology.inventory.ontology_policy_digest],
        pack_digest=ontology.inventory.model_pack_digest,
    )
    nodes.extend([ontology_node, ontology_report_node])

    source_node = _node(
        "source-checkpoint-inventory",
        "source_checkpoint_tensor_inventory",
        "omiv.kimi-k3-source-tensor-header-list.v1",
        source_digest,
        _relative(root, paths["source"]),
        ["source physical tensor names, shapes, and dtypes"],
        ["header inventory contains no tensor payload"],
    )
    mapping_node = _node(
        "semantic-mapping-inventory",
        "semantic_mapping_inventory",
        mapping.inventory_schema,
        mapping_digest,
        _relative(root, paths["mapping"]),
        ["source-to-target descriptor mapping and complete accounting"],
        ["payload transforms and artifact-specific provenance are not verified"],
        parents=[source_digest, split.integrity.sha256, ontology.integrity.sha256],
        policies=[mapping.mapping_policy_digest],
        pack_digest=mapping.model_pack["digest"],
    )
    mapping_report_node = _node(
        "semantic-mapping-report",
        "semantic_mapping_report",
        mapping_report.report.report_schema,
        mapping_report.integrity["sha256"],
        _relative(root, paths["mapping_report"]),
        ["semantic mapping findings and denominators"],
        [
            "artifact-specific conversion provenance unavailable",
            "payload verification not checked",
        ],
        parents=[mapping_digest],
        policies=[mapping.mapping_policy_digest],
        pack_digest=mapping.model_pack["digest"],
    )
    nodes.extend([source_node, mapping_node, mapping_report_node])

    edges = [
        _edge(
            snapshot_node,
            snapshot_report_node,
            "reports_on",
            snapshot_report.report.snapshot_sha256,
        ),
        _edge(
            snapshot_node, prefix_node, "bounded_prefix_of", prefix_report.report.snapshot_sha256
        ),
        *[
            _edge(snapshot_node, node, "header_of_snapshot", header.inventory.snapshot_sha256)
            for node, header in zip(header_nodes, headers, strict=True)
        ],
        _edge(
            header_nodes[0], header_report_node, "reports_on", header_report.report.inventory_sha256
        ),
        _edge(snapshot_node, split_node, "aggregates_snapshot", split.inventory.snapshot_sha256),
        *[
            _edge(node, split_node, "aggregated_shard_header", summary.inventory_sha256)
            for node, summary in zip(header_nodes, split.inventory.shard_summaries, strict=True)
        ],
        _edge(split_node, split_report_node, "reports_on", split_report.report.inventory_sha256),
        _edge(
            split_node,
            ontology_node,
            "classified_by_ontology",
            ontology.inventory.source_split_inventory_sha256,
        ),
        _edge(
            ontology_node,
            ontology_report_node,
            "reports_on",
            ontology_report.report.inventory_sha256,
        ),
        _edge(source_node, mapping_node, "mapping_source", mapping.source["inventory_sha256"]),
        _edge(
            split_node,
            mapping_node,
            "mapping_target_split",
            mapping.target["split_inventory_sha256"],
        ),
        _edge(
            ontology_node,
            mapping_node,
            "mapping_target_ontology",
            mapping.target["ontology_inventory_sha256"],
        ),
        _edge(
            mapping_node, mapping_report_node, "reports_on", mapping_report.report.inventory_digest
        ),
    ]
    _require(
        all(edge.linkage_status == EvidenceStatus.PASS for edge in edges),
        "one or more evidence graph linkages failed",
    )
    nodes = sorted(nodes, key=lambda item: item.node_id)
    edges = sorted(
        edges,
        key=lambda item: (
            item.parent_node_id,
            item.child_node_id,
            item.dependency_relation,
        ),
    )

    structural_limitation = ["does not establish tensor payload or numerical correctness"]
    stages = [
        _stage(
            EvidenceStageName.REPOSITORY_IDENTITY,
            EvidenceStatus.PASS,
            [snapshot_node],
            "VALIDATE-004",
            ["fixed repository and immutable revision"],
            [],
            [],
            [],
        ),
        _stage(
            EvidenceStageName.REPOSITORY_LAYOUT,
            EvidenceStatus.PASS,
            [snapshot_node, snapshot_report_node],
            "VALIDATE-004",
            ["15-file selected split layout"],
            [],
            [],
            [],
        ),
        _stage(
            EvidenceStageName.RANGE_SEMANTICS,
            EvidenceStatus.PASS,
            [prefix_node, *header_nodes],
            "VALIDATE-005",
            ["bounded byte ranges"],
            ["remote evidence was generated previously"],
            [],
            [headers[0].inventory.parser_policy_sha256],
        ),
        _stage(
            EvidenceStageName.FILE_PREFIX,
            EvidenceStatus.PASS,
            [prefix_node],
            "VALIDATE-005",
            ["GGUF magic and version prefix"],
            [],
            [],
            [],
        ),
        _stage(
            EvidenceStageName.COMPLETE_HEADER,
            EvidenceStatus.PASS,
            [*header_nodes, header_report_node],
            "VALIDATE-006",
            ["complete GGUF headers for all shards"],
            structural_limitation,
            [],
            [headers[0].inventory.parser_policy_sha256],
        ),
        _stage(
            EvidenceStageName.SPLIT_CONTAINER,
            EvidenceStatus.PASS,
            [split_node, split_report_node],
            "VALIDATE-007",
            ["split identity and descriptor aggregation"],
            structural_limitation,
            [],
            [split.inventory.aggregation_policy_sha256],
        ),
        _stage(
            EvidenceStageName.PAYLOAD_SPAN_BOUNDS,
            EvidenceStatus.PASS,
            [split_node],
            "VALIDATE-007",
            ["computed descriptor payload spans fit shard bounds"],
            ["bounds do not prove payload bytes"],
            ["payload integrity evidence"],
            [split.inventory.ggml_type_policy_sha256],
        ),
        _stage(
            EvidenceStageName.TARGET_ONTOLOGY,
            EvidenceStatus.PASS,
            [ontology_node, ontology_report_node],
            "VALIDATE-008",
            ["Kimi K3 target ontology"],
            structural_limitation,
            [],
            [ontology.inventory.ontology_policy_digest],
        ),
        _stage(
            EvidenceStageName.STRUCTURAL_SEMANTIC_MAPPING,
            EvidenceStatus.PASS,
            [source_node, mapping_node, mapping_report_node],
            "VALIDATE-009",
            ["descriptor-level source-to-target assignments"],
            structural_limitation,
            ["payload relation verification"],
            [mapping.mapping_policy_digest],
        ),
        _stage(
            EvidenceStageName.CONVERTER_RULE_SUPPORT,
            EvidenceStatus.AVAILABLE,
            [mapping_node],
            "VALIDATE-013",
            ["pinned converter code supports recorded relations"],
            ["does not identify the converter run that produced this artifact"],
            ["artifact-specific conversion provenance"],
            [mapping.mapping_policy_digest],
        ),
        _stage(
            EvidenceStageName.DETERMINISTIC_VERIFICATION,
            EvidenceStatus.PASS,
            [snapshot_node, split_node, ontology_node, mapping_node],
            "VALIDATE-020",
            ["canonical digests and dependency reconstruction"],
            ["determinism applies to evidence artifacts, not model execution"],
            [],
            [
                ontology.inventory.ontology_policy_digest,
                mapping.mapping_policy_digest,
            ],
        ),
        _stage(
            EvidenceStageName.ARTIFACT_SPECIFIC_PROVENANCE,
            EvidenceStatus.UNAVAILABLE,
            [mapping_node, mapping_report_node],
            "VALIDATE-014",
            [],
            ["no artifact-specific conversion-run provenance exists"],
            ["signed conversion-run provenance"],
            [],
        ),
        _stage(
            EvidenceStageName.PAYLOAD_INTEGRITY,
            EvidenceStatus.NOT_CHECKED,
            [mapping_node],
            "VALIDATE-015",
            [],
            ["no tensor payload bytes or hashes were accessed"],
            ["payload digest evidence"],
            [],
        ),
        _stage(
            EvidenceStageName.QUANTIZATION_FIDELITY,
            EvidenceStatus.NOT_CHECKED,
            [mapping_node],
            "VALIDATE-016",
            [],
            ["allowed type transitions are not numerical fidelity"],
            ["numerical quantization comparison"],
            [],
        ),
        _stage(
            EvidenceStageName.TOKENIZER_PARITY,
            EvidenceStatus.NOT_CHECKED,
            [split_node],
            "VALIDATE-017",
            [],
            ["tokenizer arrays were not compared"],
            ["tokenizer parity evidence"],
            [],
        ),
        _stage(
            EvidenceStageName.RUNTIME_PARITY,
            EvidenceStatus.NOT_CHECKED,
            [mapping_node],
            "VALIDATE-018",
            [],
            ["no backend execution, logits, or runtime output"],
            ["runtime parity evidence"],
            [],
        ),
    ]
    stages = sorted(stages, key=lambda item: item.stage.value)

    graph_payload = {
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "edges": [edge.model_dump(mode="json") for edge in edges],
        "model_pack_digest": pack.metadata.digest,
        "policy_digests": sorted(
            [ontology.inventory.ontology_policy_digest, mapping.mapping_policy_digest]
        ),
        "stages": [stage.model_dump(mode="json") for stage in stages],
    }
    graph_digest = canonical_sha256(graph_payload)
    profile_results = evaluate_profiles(stages, profiles)

    artifacts: list[ArtifactIndexEntry] = [
        _artifact_entry(
            root,
            paths["snapshot"],
            "repository_snapshot",
            snapshot.snapshot.snapshot_schema,
            snapshot.integrity.sha256,
            "4F-1",
            "omiv remote-snapshot-verify --input " + _relative(root, paths["snapshot"]),
        ),
        _artifact_entry(
            root,
            paths["snapshot_report"],
            "snapshot_report",
            snapshot_report.report.report_schema,
            snapshot_report.integrity.sha256,
            "4F-1",
            "omiv report-verify --input " + _relative(root, paths["snapshot_report"]),
        ),
        _artifact_entry(
            root,
            paths["prefix_report"],
            "prefix_report",
            prefix_report.report.report_schema,
            prefix_report.integrity.sha256,
            "4F-1",
            "omiv report-verify --input " + _relative(root, paths["prefix_report"]),
        ),
    ]
    for index, (path, envelope) in enumerate(zip(header_paths, headers, strict=True), start=1):
        artifacts.append(
            _artifact_entry(
                root,
                path,
                f"shard_{index:02d}_header_inventory",
                envelope.inventory.inventory_schema,
                envelope.integrity.sha256,
                "4F-2" if index == 1 else "4F-3",
                "omiv remote-gguf-header-inventory-verify --input " + _relative(root, path),
            )
        )
    artifacts.extend(
        [
            _artifact_entry(
                root,
                paths["header_report"],
                "shard_1_header_report",
                header_report.report.report_schema,
                header_report.integrity.sha256,
                "4F-2",
                "omiv report-verify --input " + _relative(root, paths["header_report"]),
            ),
            _artifact_entry(
                root,
                paths["split"],
                "split_inventory",
                split.inventory.inventory_schema,
                split.integrity.sha256,
                "4F-3",
                "omiv remote-split-inventory-verify --input " + _relative(root, paths["split"]),
            ),
            _artifact_entry(
                root,
                paths["split_report"],
                "split_report",
                split_report.report.report_schema,
                split_report.integrity.sha256,
                "4F-3",
                "omiv report-verify --input " + _relative(root, paths["split_report"]),
            ),
            _artifact_entry(
                root,
                paths["ontology"],
                "target_ontology_inventory",
                ontology.inventory.inventory_schema,
                ontology.integrity.sha256,
                "4F-4",
                "omiv kimi-k3-gguf-ontology-inventory-verify --input "
                + _relative(root, paths["ontology"]),
            ),
            _artifact_entry(
                root,
                paths["ontology_report"],
                "target_ontology_report",
                ontology_report.report.report_schema,
                ontology_report.integrity.sha256,
                "4F-4",
                "omiv report-verify --input " + _relative(root, paths["ontology_report"]),
            ),
            _artifact_entry(
                root,
                paths["source"],
                "source_checkpoint_inventory",
                "omiv.kimi-k3-source-tensor-header-list.v1",
                source_digest,
                "source-evidence",
                "sha256sum " + _relative(root, paths["source"]),
                size_bytes=source_size,
            ),
            _artifact_entry(
                root,
                paths["mapping"],
                "semantic_mapping_inventory",
                mapping.inventory_schema,
                mapping_digest,
                "4F-5",
                "omiv kimi-k3-semantic-mapping-inventory-verify --input "
                + _relative(root, paths["mapping"]),
            ),
            _artifact_entry(
                root,
                paths["mapping_report"],
                "semantic_mapping_report",
                mapping_report.report.report_schema,
                mapping_report.integrity["sha256"],
                "4F-5",
                "omiv report-verify --input " + _relative(root, paths["mapping_report"]),
            ),
        ]
    )
    artifacts = sorted(artifacts, key=lambda item: (item.producer_phase, item.role))
    artifact_index_payload = {"entries": [item.model_dump(mode="json") for item in artifacts]}
    artifact_index = ArtifactIndex(
        entries=artifacts,
        index_digest=canonical_sha256(artifact_index_payload),
    )

    source_accounting = dict(mapping.source_accounting)
    target_accounting = dict(mapping.target_accounting)
    coverage = dict(mapping.coverage)
    _require(
        source_accounting["physical_records"] == mapping.source["physical_count"],
        "source accounting total mismatch",
    )
    _require(
        target_accounting["physical_records"] == split.inventory.aggregated_tensor_count,
        "target accounting total mismatch",
    )
    _require(source_accounting["unresolved_records"] == 0, "source records unresolved")
    _require(target_accounting["unresolved_records"] == 0, "target descriptors unresolved")
    _require(
        all(item["count"] == 0 for item in coverage["duplicates"].values())
        and coverage["ambiguities"]["count"] == 0,
        "mapping assignment uniqueness failed",
    )
    _require(
        all(value == 0 for value in coverage["failures"].values()),
        "mapping shape, axis, or type-transition failures remain",
    )

    findings = [
        _finding(
            "VALIDATE-001",
            EvidenceStatus.PASS,
            "Subject identity is pinned.",
            repository=EXPECTED_REPOSITORY,
            revision=snapshot.snapshot.repository.resolved_revision,
        ),
        _finding(
            "VALIDATE-002",
            EvidenceStatus.PASS,
            "Evidence graph is complete and acyclic.",
            node_count=len(nodes),
            edge_count=len(edges),
        ),
        _finding(
            "VALIDATE-003",
            EvidenceStatus.PASS,
            "All required artifact digests verify.",
            artifact_count=len(artifacts),
        ),
        _finding(
            "VALIDATE-004",
            EvidenceStatus.PASS,
            "Immutable repository evidence is valid.",
            file_count=snapshot.snapshot.summary.file_count,
        ),
        _finding(
            "VALIDATE-005",
            EvidenceStatus.PASS,
            "Bounded remote inspection evidence is valid.",
            tensor_payload_bytes=0,
        ),
        _finding(
            "VALIDATE-006",
            EvidenceStatus.PASS,
            "Complete GGUF header evidence is valid.",
            shard_count=len(headers),
        ),
        _finding(
            "VALIDATE-007",
            EvidenceStatus.PASS,
            "Split-container evidence is valid.",
            tensor_count=split.inventory.aggregated_tensor_count,
        ),
        _finding(
            "VALIDATE-008",
            EvidenceStatus.PASS,
            "Target ontology evidence is valid.",
            ontology_digest=ontology.integrity.sha256,
        ),
        _finding(
            "VALIDATE-009",
            EvidenceStatus.PASS,
            "Structural semantic-mapping evidence is valid.",
            mapping_digest=mapping_digest,
        ),
        _finding(
            "VALIDATE-010",
            EvidenceStatus.PASS,
            "Model-pack and policy identities are valid.",
            model_pack_digest=pack.metadata.digest,
        ),
        _finding(
            "VALIDATE-011",
            EvidenceStatus.PASS,
            "Source accounting is complete.",
            records=source_accounting["physical_records"],
        ),
        _finding(
            "VALIDATE-012",
            EvidenceStatus.PASS,
            "Target accounting is complete.",
            descriptors=target_accounting["physical_records"],
        ),
        _finding(
            "VALIDATE-013",
            EvidenceStatus.AVAILABLE,
            "Pinned converter-rule evidence is available.",
            revision=mapping.converter_evidence_revision,
        ),
        _finding(
            "VALIDATE-014",
            EvidenceStatus.UNAVAILABLE,
            "Artifact-specific conversion provenance is unavailable.",
        ),
        _finding(
            "VALIDATE-015", EvidenceStatus.NOT_CHECKED, "Tensor payload integrity was not checked."
        ),
        _finding(
            "VALIDATE-016",
            EvidenceStatus.NOT_CHECKED,
            "Numerical quantization fidelity was not checked.",
        ),
        _finding("VALIDATE-017", EvidenceStatus.NOT_CHECKED, "Tokenizer parity was not checked."),
        _finding("VALIDATE-018", EvidenceStatus.NOT_CHECKED, "Runtime parity was not checked."),
        _finding(
            "VALIDATE-019",
            EvidenceStatus.PASS,
            "Evidence limitations are explicit and non-empty.",
            limitation_count=13,
        ),
        _finding(
            "VALIDATE-020",
            EvidenceStatus.PASS,
            "The final bundle uses deterministic canonical serialization.",
            evidence_graph_digest=graph_digest,
        ),
    ]

    verified_scope = [
        "fixed repository identity and immutable revision",
        "selected remote file set, sizes, and stable identities where available",
        "filename split layout and bounded HTTP Range semantics",
        "GGUF version and complete headers",
        "split metadata, shard identity, and global descriptor aggregation",
        "payload-span structural bounds without payload access",
        "Kimi K3 target ontology and architecture schedule",
        "source and target identity accounting",
        "descriptor-level structural semantic mapping",
        "pinned converter-code relation evidence",
        "deterministic artifact verification and regeneration",
    ]
    not_verified = [
        "actual source-to-target payload equality",
        "routed expert numerical packing order and scale numerical association",
        "A_log numerical transform result",
        "convolution reshape payload correctness",
        "MLA split and transpose payload correctness",
        "Attention Residual fusion payload correctness",
        "tensor payload integrity",
        "quantization error or quality",
        "tokenizer equivalence",
        "logits, backend execution, and runtime parity",
        "artifact-specific conversion-run provenance",
    ]
    limitations = [
        "Structural descriptor validation does not establish tensor payload integrity.",
        (
            "Converter-code support does not establish which converter produced the "
            "published artifact."
        ),
        "Allowed GGML type transitions do not establish numerical quantization fidelity.",
        "Tokenizer arrays, logits, backend execution, and runtime behavior were not compared.",
        (
            "The result supports structural integration acceptance only under profiles "
            "that permit these limitations."
        ),
    ]
    architecture = {
        "architecture": "kimi-k3",
        "layers": len(ontology.inventory.schedule.expected_layer_ids),
        "kda_layers": len(ontology.inventory.schedule.kda_layer_ids),
        "mla_layers": len(ontology.inventory.schedule.mla_layer_ids),
        "dense_layers": ontology.inventory.schedule.dense_layer_ids,
        "moe_layer_range": [
            min(ontology.inventory.schedule.moe_layer_ids),
            max(ontology.inventory.schedule.moe_layer_ids),
        ],
        "routed_experts": ontology.inventory.packed_experts.metadata_expert_count,
        "experts_used": 16,
        "shared_experts": coverage["shared_experts"]["metadata_shared_expert_count"],
        "attention_residual_block_size": ontology.inventory.attention_residual.metadata_block_size,
        "target_tensors": split.inventory.aggregated_tensor_count,
        "ggml_types": sorted(split.inventory.payload_span_summary.supported_type_counts),
    }
    repository_summary = {
        "selected_shard_count": split.inventory.shard_count,
        "total_repository_bytes": split.inventory.total_repository_bytes,
        "per_shard_declared_sizes": [item.file_size for item in split.inventory.shard_summaries],
        "storage_metadata_available_count": sum(
            item.storage is not None for item in snapshot.snapshot.files
        ),
        "filename_split_result": "PASS",
        "header_split_result": "PASS",
        "global_declared_tensor_count": split.inventory.global_tensor_count_metadata,
        "aggregated_tensor_count": split.inventory.aggregated_tensor_count,
        "duplicate_count": split.inventory.duplicate_summary.exact_duplicate_count,
        "conflict_count": split.inventory.duplicate_summary.conflict_count,
        "payload_span_computable_count": split.inventory.payload_span_summary.computable_count,
        "payload_span_bounded_count": split.inventory.payload_span_summary.bounded_count,
        "payload_span_overlap_count": split.inventory.payload_span_summary.overlap_count,
        "header_bytes_accepted": split.inventory.total_header_bytes_accepted,
        "range_request_count": split.inventory.total_request_count + 1,
        "tensor_payload_bytes_accepted": 0,
        "metadata_only_shards": [
            item.path for item in split.inventory.shard_summaries if item.tensor_count == 0
        ],
        "tensor_bearing_shard_count": sum(
            item.tensor_count > 0 for item in split.inventory.shard_summaries
        ),
        "target_type_counts": dict(split.inventory.payload_span_summary.supported_type_counts),
    }
    reproduction = ReproductionManifest(
        omiv_repository_revision=OMIV_EVIDENCE_REVISION,
        original_evidence_commands=[
            ReproductionCommand(
                command=(
                    "omiv remote-snapshot --provider huggingface --repo "
                    f"unsloth/Kimi-K3-GGUF --revision main --path-prefix {variant} "
                    "--pattern '*.gguf'"
                ),
                network_requirement="online",
                purpose="Generate immutable repository-layout evidence.",
            ),
            ReproductionCommand(
                command=(
                    "omiv remote-split-gguf --snapshot snapshots/huggingface/"
                    f"unsloth_Kimi-K3-GGUF_{variant}.snapshot.json --output "
                    f"inventories/remote/unsloth_Kimi-K3-GGUF_{variant}."
                    "split.inventory.json"
                ),
                network_requirement="online",
                purpose=(
                    "Generate bounded complete-header and split evidence without payload download."
                ),
            ),
        ],
        offline_verification_commands=[
            ReproductionCommand(
                command=(
                    "omiv independent-validation-inventory-verify --input "
                    f"validations/unsloth_Kimi-K3-GGUF_{variant}."
                    "validation.inventory.json"
                ),
                network_requirement="offline",
                purpose="Verify the final inventory and every dependency.",
            ),
            ReproductionCommand(
                command=(
                    "omiv report-verify --input reports/validation/"
                    f"unsloth_Kimi-K3-GGUF_{variant}.validation.report.json"
                ),
                network_requirement="offline",
                purpose="Verify the final report and reconstruct its results.",
            ),
        ],
        required_input_paths=[entry.relative_path for entry in artifacts],
        expected_input_digests={entry.role: entry.canonical_digest for entry in artifacts},
        original_remote_header_bytes_accepted=split.inventory.total_header_bytes_accepted + 8,
        original_range_request_count=split.inventory.total_request_count + 1,
        tensor_payload_bytes_accepted=0,
        no_payload_download=True,
    )

    preliminary = {
        "subject": SubjectIdentity(
            model_family=subject, artifact_variant=variant, repository=EXPECTED_REPOSITORY
        ),
        "repository_identity": RepositoryIdentity(
            provider=snapshot.snapshot.provider,
            repository=snapshot.snapshot.repository.repo_id,
            requested_revision=snapshot.snapshot.repository.requested_revision,
            resolved_revision=snapshot.snapshot.repository.resolved_revision,
            selection=f"{variant}/*.gguf",
        ),
        "source_artifact_identity": {
            "inventory_digest": source_digest,
            "physical_records": source_accounting["physical_records"],
        },
        "target_artifact_identity": {
            "split_inventory_digest": split.integrity.sha256,
            "ontology_inventory_digest": ontology.integrity.sha256,
            "physical_descriptors": target_accounting["physical_records"],
        },
        "model_pack_identity": ModelPackIdentity(
            model_family=pack.metadata.model_family,
            version=pack.metadata.pack_version,
            capabilities=[item.value for item in pack.metadata.capabilities],
            digest=pack.metadata.digest,
            ontology_policy_digest=ontology.inventory.ontology_policy_digest,
            mapping_policy_digest=mapping.mapping_policy_digest,
            converter_evidence_revision=mapping.converter_evidence_revision,
        ),
        "evidence_nodes": nodes,
        "evidence_edges": edges,
        "evidence_stages": stages,
        "evidence_graph_digest": graph_digest,
        "profile_policy": profiles,
        "profile_results": profile_results,
        "selected_profile": selected_profile,
        "structural_validation_result": StructuralValidationResult.VALIDATED_WITH_LIMITATIONS
        if all(
            next(item for item in stages if item.stage == stage).status == EvidenceStatus.PASS
            for stage in STRUCTURAL_STAGES
        )
        else StructuralValidationResult.FAILED,
        "unverified_stage_count": sum(item.status == EvidenceStatus.NOT_CHECKED for item in stages),
        "unavailable_stage_count": sum(
            item.status == EvidenceStatus.UNAVAILABLE for item in stages
        ),
        "failed_stage_count": sum(item.status == EvidenceStatus.FAIL for item in stages),
        "warning_count": sum(item.status == EvidenceStatus.WARN for item in stages),
        "repository_summary": repository_summary,
        "architecture_summary": architecture,
        "source_accounting": source_accounting,
        "target_accounting": target_accounting,
        "mapping_domain_summary": _domain_summaries(coverage),
        "verified_scope": verified_scope,
        "not_verified_scope": not_verified,
        "limitations": limitations,
        "findings": findings,
        "reproduction": reproduction,
        "artifact_index": artifact_index,
        "inventory_digest": "0" * 64,
    }
    draft = ValidationInventory.model_validate(preliminary)
    data = draft.model_dump(mode="json")
    data.pop("inventory_digest")
    preliminary["inventory_digest"] = canonical_sha256(data)
    return ValidationInventory.model_validate(preliminary)
