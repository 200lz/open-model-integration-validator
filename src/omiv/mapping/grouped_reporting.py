"""Deterministic envelopes and verification for grouped mappings."""

from __future__ import annotations

import json
from pathlib import Path

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.mapping.grouped_models import MappingEnvelope, MappingInventory, MappingReport

SCHEMA = "omiv.semantic-mapping-report.v3"


def make_inventory(value: MappingInventory) -> MappingInventory:
    data = value.model_dump(mode="json", by_alias=True)
    data["inventory_digest"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "inventory_digest"}
    )
    return MappingInventory.model_validate(data)


def make_report(inv: MappingInventory) -> MappingEnvelope:
    summary = {
        "source": inv.source_accounting,
        "target": inv.target_accounting,
        "coverage": inv.coverage,
        "kimi": inv.kimi_summary,
    }
    report = MappingReport(
        inventory_digest=inv.inventory_digest or "",
        source=inv.source,
        target=inv.target,
        model_pack=inv.model_pack,
        mapping_policy_digest=inv.mapping_policy_digest,
        converter_evidence_revision=inv.converter_evidence_revision,
        artifact_specific_provenance=inv.coverage["artifact_specific_provenance"],
        payload_status=inv.coverage["payload_status"],
        summary=summary,
        findings=inv.findings,
    )
    return MappingEnvelope(
        report=report,
        integrity={
            "canonicalization": CANONICALIZATION_ID,
            "sha256": canonical_sha256(report.model_dump(mode="json")),
        },
    )


def write_mapping_artifacts(
    inv: MappingInventory, output: Path, report_output: Path, markdown_output: Path
) -> tuple[MappingInventory, MappingEnvelope]:
    inv = make_inventory(inv)
    env = make_report(inv)
    output.parent.mkdir(parents=True, exist_ok=True)
    report_output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(inv.model_dump(mode="json", by_alias=True), sort_keys=True, indent=2) + "\n"
    )
    report_output.write_text(
        json.dumps(env.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
    )
    lines = [
        "# Kimi K3 semantic mapping report",
        "",
        f"- Inventory digest: `{inv.inventory_digest}`",
        f"- Source inventory digest: `{inv.source['inventory_sha256']}`",
        f"- Target split inventory digest: `{inv.target['split_inventory_sha256']}`",
        f"- Target ontology inventory digest: `{inv.target['ontology_inventory_sha256']}`",
        (
            f"- Model pack: `{inv.model_pack['pack_id']}` v{inv.model_pack['pack_version']} "
            f"`{inv.model_pack['digest']}`"
        ),
        f"- Model-pack capabilities: `{', '.join(inv.model_pack['capabilities'])}`",
        f"- Mapping policy digest: `{inv.mapping_policy_digest}`",
        f"- Converter evidence revision: `{inv.converter_evidence_revision}`",
        f"- Artifact-specific provenance: `{inv.coverage['artifact_specific_provenance']}`",
        f"- Payload verification: `{inv.coverage['payload_status']}`",
        "",
        "## Accounting",
        "",
        "| Side | Accounted | Total | Unresolved |",
        "|---|---:|---:|---:|",
        (
            f"| Source | {inv.source_accounting['accounted']} | "
            f"{inv.source_accounting['physical_records']} | "
            f"{inv.source_accounting['unresolved_records']} |"
        ),
        (
            f"| Target | {inv.target_accounting['accounted']} | "
            f"{inv.target_accounting['physical_records']} | "
            f"{inv.target_accounting['unresolved_records']} |"
        ),
        "",
        "### Source states",
        "",
        "| State | Count |",
        "|---|---:|",
    ]
    lines += [
        f"| `{state}` | {count} |" for state, count in inv.source_accounting["states"].items()
    ]
    lines += [
        "",
        "### Target states",
        "",
        "| State | Count |",
        "|---|---:|",
    ]
    lines += [
        f"| `{state}` | {count} |" for state, count in inv.target_accounting["states"].items()
    ]
    routed = inv.coverage["routed"]
    shared = inv.coverage["shared_experts"]
    lines += [
        "",
        "## Mapping denominators",
        "",
        "| Domain | Numerator | Denominator |",
        "|---|---:|---:|",
        f"| Routed source groups | {routed['complete_groups']} | {routed['source_groups']} |",
        f"| Routed packed targets | {routed['packed_targets']} | 276 |",
        f"| Routed expert records | {routed['source_expert_members']} | 247296 |",
        f"| Routed scale records | {routed['source_scale_records']} | 247296 |",
        (
            f"| Shared physical mappings | {shared['physical_target_mappings']} | "
            f"{shared['expected_physical_mappings']} |"
        ),
        (
            f"| Direct target mappings | {inv.coverage['direct']['target_records']} | "
            f"{inv.coverage['direct']['source_records']} |"
        ),
        f"| Fused targets | {inv.coverage['fused']['targets']} | 187 |",
        f"| Logical source records | {inv.coverage['logical']['source_records']} | 393 |",
        f"| Logical target records | {inv.coverage['logical']['target_records']} | 417 |",
        "",
        "## Source auxiliary families",
        "",
        "| Family | Count | Reason |",
        "|---|---:|---|",
    ]
    lines += [
        f"| `{item['family']}` | {item['count']} | {item['reason']} |"
        for item in inv.source_accounting["auxiliary_family_breakdown"]
    ]
    lines += [
        "",
        "## Family coverage",
        "",
        "| Family | Coverage |",
        "|---|---:|",
        (
            f"| Router / router bias | {inv.coverage['router']['router']} / "
            f"{inv.coverage['router']['router_bias']} |"
        ),
        (
            f"| Latent MoE up / down / norm | {inv.coverage['latent_moe']['up']} / "
            f"{inv.coverage['latent_moe']['down']} / {inv.coverage['latent_moe']['norm']} |"
        ),
        (
            f"| Dense layer 0 gate / up / down | {inv.coverage['dense']['gate']} / "
            f"{inv.coverage['dense']['up']} / {inv.coverage['dense']['down']} |"
        ),
        (
            f"| Attention norm / FFN norm / output norm | "
            f"{inv.coverage['norms']['attention']} / {inv.coverage['norms']['ffn']} / "
            f"{inv.coverage['norms']['output']} |"
        ),
        f"| Attention output | {inv.coverage['attention_output']} |",
        (
            f"| KDA direct / logical transform | {inv.coverage['kda']['direct']} / "
            f"{inv.coverage['kda']['logical']} |"
        ),
        (
            f"| MLA direct / split sources / split targets | "
            f"{inv.coverage['mla']['direct']} / {inv.coverage['mla']['split_sources']} / "
            f"{inv.coverage['mla']['split_targets']} |"
        ),
        (
            f"| Attention Residual fused members / targets | "
            f"{inv.coverage['fused']['source_members']} / {inv.coverage['fused']['targets']} |"
        ),
        (
            f"| g_proj KDA / MLA / total | {inv.coverage['g_proj']['kda']} / "
            f"{inv.coverage['g_proj']['mla']} / {inv.coverage['g_proj']['total']} |"
        ),
        f"| Model-level direct | {inv.coverage['model_level_direct']} |",
        "",
        (
            "Shared-expert metadata records two logical shared experts; the combined "
            "gate/up/down projections are mapped one-to-one. A separate shared routing/"
            "mixing gate is absent/not applicable. Shared partition/order is NOT_CHECKED."
        ),
        "",
        "## Type transitions and validation",
        "",
        "| Source dtype | Physical records |",
        "|---|---:|",
    ]
    transition = inv.coverage["type_transition_summary"]
    lines += [
        f"| `{dtype}` | {count} |" for dtype, count in transition["source_dtype_counts"].items()
    ]
    lines += [
        "",
        "| Target GGML type | Physical targets |",
        "|---|---:|",
    ]
    lines += [
        f"| `{ggml_type}` | {count} |"
        for ggml_type, count in transition["target_ggml_type_counts"].items()
    ]
    duplicates = inv.coverage["duplicates"]
    failures = inv.coverage["failures"]
    lines += [
        "",
        (
            "Transition failures: "
            f"{transition['failures']}; shape failures: {failures['shape']}; "
            f"axis failures: {failures['axis']}."
        ),
        "",
        "| Duplicate or ambiguity class | Count |",
        "|---|---:|",
        (
            "| Duplicate source physical assignments | "
            f"{duplicates['duplicate_source_physical']['count']} |"
        ),
        (
            "| Duplicate source logical assignments | "
            f"{duplicates['duplicate_source_logical']['count']} |"
        ),
        (
            "| Duplicate target physical assignments | "
            f"{duplicates['duplicate_target_physical']['count']} |"
        ),
        (
            "| Duplicate mapping-result identities | "
            f"{duplicates['duplicate_mapping_result']['count']} |"
        ),
        (
            "| Duplicate source-group assignments | "
            f"{duplicates['duplicate_source_group']['count']} |"
        ),
        f"| Ambiguous lookups | {inv.coverage['ambiguities']['count']} |",
        "",
        "## Unresolved families",
        "",
        (
            f"- Source unresolved: {inv.source_accounting['unresolved_records']} "
            f"across {len(inv.source_accounting['unresolved_family_breakdown'])} families."
        ),
        (
            f"- Target unresolved: {inv.target_accounting['unresolved_records']} "
            f"across {len(inv.target_accounting['unresolved_family_breakdown'])} families."
        ),
        "",
        "## Findings",
    ]
    lines += [f"- **{f.status}** {f.code}: {f.message}" for f in inv.findings]
    lines += [
        "",
        "Payload packing correctness: NOT_CHECKED.",
        "Descriptor-level structural mapping does not prove payload order, "
        "quantization fidelity, or runtime parity.",
    ]
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.write_text("\n".join(lines) + "\n")
    return inv, env


def load_mapping_inventory(path: Path) -> MappingInventory:
    return MappingInventory.model_validate(json.loads(path.read_text()))


def load_mapping_report(path: Path) -> MappingEnvelope:
    return MappingEnvelope.model_validate(json.loads(path.read_text()))


def mapping_report_integrity_matches(env: MappingEnvelope) -> bool:
    return env.integrity.get("sha256") == canonical_sha256(env.report.model_dump(mode="json"))
