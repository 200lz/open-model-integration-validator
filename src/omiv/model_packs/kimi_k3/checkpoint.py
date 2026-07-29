"""Normalize a raw Kimi K3 safetensors-header inventory."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from omiv.errors import OmivInputError
from omiv.model_packs.kimi_k3.contracts import PHASE1_EXPERT_COMPONENT_SET
from omiv.models import (
    AttentionInventory,
    AttentionKind,
    CompactUnclassifiedGroups,
    DescriptorGroup,
    DescriptorSummary,
    Diagnostic,
    ExpertCoverage,
    FfnInventory,
    FfnKind,
    LayerExpertPair,
    LayerInventory,
    ModelInventory,
    SemanticDescriptorInventory,
    Severity,
    SourceSummary,
    TensorClassificationSummary,
    UnclassifiedGroup,
    json_compatible,
)

LAYER_RE = re.compile(r"^language_model\.model\.layers\.(\d+)\.")
EXPERT_RE = re.compile(
    r"^language_model\.model\.layers\.(\d+)\.block_sparse_moe\.experts\.(\d+)"
    r"\.(w[123])\.(weight_packed|weight_scale)$"
)
DENSE_RE = re.compile(
    r"^language_model\.model\.layers\.(\d+)\.mlp\.(gate_proj|up_proj|down_proj)\.weight$"
)
SHARED_RE = re.compile(
    r"^language_model\.model\.layers\.(\d+)\.block_sparse_moe\.shared_experts\."
    r"(.+)$"
)
SELF_ATTN_RE = re.compile(r"^language_model\.model\.layers\.(\d+)\.self_attn\.(.+)$")
LAYER_RESIDUAL_RE = re.compile(
    r"^language_model\.model\.layers\.(\d+)\."
    r"((?:self_attention_res|mlp_res)_.+)$"
)
MODEL_RESIDUAL_RE = re.compile(r"^language_model\.model\.(output_attn_res_.+)$")
MOE_NAMESPACE_RE = re.compile(r"^language_model\.model\.layers\.(\d+)\.block_sparse_moe\.")

KDA_MARKERS = frozenset(
    {
        "A_log",
        "dt_bias",
        "b_proj.weight",
        "f_a_proj.weight",
        "f_b_proj.weight",
        "q_proj.weight",
        "k_proj.weight",
        "v_proj.weight",
        "q_conv1d.weight",
        "k_conv1d.weight",
        "v_conv1d.weight",
        "o_norm.weight",
    }
)
MLA_MARKERS = frozenset(
    {
        "q_a_proj.weight",
        "q_a_layernorm.weight",
        "q_b_proj.weight",
        "kv_a_proj_with_mqa.weight",
        "kv_a_layernorm.weight",
        "kv_b_proj.weight",
    }
)
DENSE_COMPONENTS = frozenset({"gate_proj.weight", "up_proj.weight", "down_proj.weight"})

DESCRIPTOR_ENTITY_EXAMPLE_CAP = 12
UNCLASSIFIED_GROUP_CAP = 100
UNCLASSIFIED_EXAMPLES_PER_GROUP_CAP = 3


@dataclass
class _DescriptorGroupState:
    observation_count: int = 0
    layer_ids: set[int] = field(default_factory=set)
    layer_expert_examples: set[tuple[int, int]] = field(default_factory=set)


@dataclass
class _DescriptorAccumulator:
    groups: dict[tuple[str, tuple[int, ...]], _DescriptorGroupState] = field(default_factory=dict)

    def observe(
        self,
        dtype: str,
        shape: tuple[int, ...],
        *,
        layer_id: int | None = None,
        expert_id: int | None = None,
    ) -> None:
        state = self.groups.setdefault((dtype, shape), _DescriptorGroupState())
        state.observation_count += 1
        if layer_id is not None:
            state.layer_ids.add(layer_id)
        if layer_id is not None and expert_id is not None:
            state.layer_expert_examples.add((layer_id, expert_id))
            if len(state.layer_expert_examples) > DESCRIPTOR_ENTITY_EXAMPLE_CAP:
                state.layer_expert_examples.remove(max(state.layer_expert_examples))

    def summary(self) -> DescriptorSummary:
        groups = []
        for (dtype, shape), state in sorted(self.groups.items()):
            groups.append(
                DescriptorGroup(
                    dtype=dtype,
                    shape=list(shape),
                    observation_count=state.observation_count,
                    layer_ids=sorted(state.layer_ids),
                    layer_expert_pair_examples=[
                        LayerExpertPair(layer_id=layer_id, expert_id=expert_id)
                        for layer_id, expert_id in sorted(state.layer_expert_examples)
                    ],
                )
            )
        return DescriptorSummary(
            observation_count=sum(group.observation_count for group in groups),
            descriptor_groups=groups,
        )


@dataclass
class _UnclassifiedAccumulator:
    counts: Counter[str] = field(default_factory=Counter)
    examples: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def observe(self, key: str, name: str) -> None:
        self.counts[key] += 1
        samples = self.examples[key]
        samples.add(name)
        if len(samples) > UNCLASSIFIED_EXAMPLES_PER_GROUP_CAP:
            samples.remove(max(samples))

    def compact(self) -> CompactUnclassifiedGroups:
        selected = sorted(self.counts, key=lambda key: (-self.counts[key], key))[
            :UNCLASSIFIED_GROUP_CAP
        ]
        groups = [
            UnclassifiedGroup(
                key=key,
                record_count=self.counts[key],
                examples=sorted(self.examples[key]),
            )
            for key in selected
        ]
        return CompactUnclassifiedGroups(
            record_count=sum(self.counts.values()),
            group_count=len(self.counts),
            emitted_group_count=len(groups),
            omitted_group_count=len(self.counts) - len(groups),
            groups=groups,
        )


@dataclass
class _LayerState:
    attention_markers: set[str] = field(default_factory=set)
    g_proj_observation_count: int = 0
    dense_components: set[str] = field(default_factory=set)
    moe_namespace_present: bool = False
    experts: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    shared_components: set[str] = field(default_factory=set)
    residual_components: set[str] = field(default_factory=set)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_record(record: object, index: int) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise OmivInputError(f"record {index} must be an object")
    required = {"name", "dtype", "shape", "shard", "header_len", "offsets"}
    keys = set(record)
    if keys != required:
        raise OmivInputError(
            f"record {index} fields differ from contract: "
            f"missing={sorted(required - keys)}, unexpected={sorted(keys - required)}"
        )
    if not isinstance(record["name"], str) or not record["name"]:
        raise OmivInputError(f"record {index} name must be a non-empty string")
    if not isinstance(record["dtype"], str) or not record["dtype"]:
        raise OmivInputError(f"record {index} dtype must be a non-empty string")
    if not isinstance(record["shard"], str) or not record["shard"]:
        raise OmivInputError(f"record {index} shard must be a non-empty string")
    shape = record["shape"]
    if not isinstance(shape, list) or not all(_valid_int(v) and v >= 0 for v in shape):
        raise OmivInputError(f"record {index} shape must be a list of non-negative integers")
    if not _valid_int(record["header_len"]) or record["header_len"] < 0:
        raise OmivInputError(f"record {index} header_len must be a non-negative integer")
    offsets = record["offsets"]
    if (
        not isinstance(offsets, list)
        or len(offsets) != 2
        or not all(_valid_int(v) and v >= 0 for v in offsets)
        or offsets[0] > offsets[1]
    ):
        raise OmivInputError(f"record {index} offsets must be two ordered non-negative integers")
    return record


def iter_raw_records(path: Path) -> Iterator[object]:
    """Incrementally decode values from a top-level JSON array.

    This deliberately exposes an iterator boundary so another streaming parser can
    replace the standard-library decoder without changing normalization logic.
    """
    decoder = json.JSONDecoder()
    chunk_size = 1024 * 1024
    try:
        handle = path.open(encoding="utf-8")
    except OSError as exc:
        raise OmivInputError(f"cannot read raw inventory: {exc}") from exc

    with handle:
        buffer = ""
        position = 0
        eof = False

        def compact_and_fill() -> None:
            nonlocal buffer, position, eof
            buffer = buffer[position:]
            position = 0
            chunk = handle.read(chunk_size)
            if chunk:
                buffer += chunk
            else:
                eof = True

        def skip_space() -> None:
            nonlocal position
            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if position < len(buffer) or eof:
                    return
                compact_and_fill()

        compact_and_fill()
        skip_space()
        if position >= len(buffer) or buffer[position] != "[":
            raise OmivInputError("raw inventory must be a top-level JSON array")
        position += 1
        skip_space()
        if position < len(buffer) and buffer[position] == "]":
            position += 1
        else:
            while True:
                buffer = buffer[position:]
                position = 0
                if not buffer and not eof:
                    chunk = handle.read(chunk_size)
                    if chunk:
                        buffer = chunk
                    else:
                        eof = True
                while True:
                    try:
                        value, end = decoder.raw_decode(buffer)
                        position = end
                        break
                    except json.JSONDecodeError as exc:
                        incomplete = not eof and (
                            exc.pos >= len(buffer) - 1 or exc.msg.startswith("Unterminated string")
                        )
                        if not incomplete:
                            raise OmivInputError(
                                f"malformed JSON array near character {exc.pos}: {exc.msg}"
                            ) from exc
                        chunk = handle.read(chunk_size)
                        if chunk:
                            buffer += chunk
                        else:
                            eof = True
                yield value
                skip_space()
                if position >= len(buffer):
                    raise OmivInputError("unterminated top-level JSON array")
                delimiter = buffer[position]
                position += 1
                if delimiter == "]":
                    break
                if delimiter != ",":
                    raise OmivInputError("raw inventory array records must be separated by commas")
                skip_space()

        while True:
            skip_space()
            if position < len(buffer):
                raise OmivInputError("unexpected data after top-level JSON array")
            if eof:
                break
            compact_and_fill()


def _classify_attention(
    layer_id: int, state: _LayerState, diagnostics: list[Diagnostic]
) -> AttentionKind:
    kda = state.attention_markers & KDA_MARKERS
    mla = state.attention_markers & MLA_MARKERS
    if kda and mla:
        diagnostics.append(
            Diagnostic(
                code="CONFLICTING_ATTENTION_SIGNATURE",
                severity=Severity.ERROR,
                message=f"layer {layer_id} contains both KDA and MLA evidence",
                evidence={
                    "layer_id": layer_id,
                    "kda_markers": json_compatible(sorted(kda)),
                    "mla_markers": json_compatible(sorted(mla)),
                },
            )
        )
        return AttentionKind.CONFLICT
    if kda == KDA_MARKERS:
        return AttentionKind.KDA
    if mla == MLA_MARKERS:
        return AttentionKind.MLA
    if kda or mla:
        family = "KDA" if kda else "MLA"
        observed = kda or mla
        required = KDA_MARKERS if kda else MLA_MARKERS
        diagnostics.append(
            Diagnostic(
                code="PARTIAL_ATTENTION_SIGNATURE",
                severity=Severity.WARNING,
                message=f"layer {layer_id} has an incomplete {family} marker family",
                evidence={
                    "layer_id": layer_id,
                    "family": family.lower(),
                    "missing_markers": json_compatible(sorted(required - observed)),
                },
            )
        )
    return AttentionKind.UNKNOWN


def _classify_ffn(layer_id: int, state: _LayerState, diagnostics: list[Diagnostic]) -> FfnKind:
    dense_complete = state.dense_components == DENSE_COMPONENTS
    dense_evidence = bool(state.dense_components)
    moe_evidence = state.moe_namespace_present and bool(state.experts)
    if dense_evidence and state.moe_namespace_present:
        diagnostics.append(
            Diagnostic(
                code="CONFLICTING_FFN_SIGNATURE",
                severity=Severity.ERROR,
                message=f"layer {layer_id} contains both dense and MoE evidence",
                evidence={
                    "layer_id": layer_id,
                    "dense_components": json_compatible(sorted(state.dense_components)),
                    "moe_namespace_present": True,
                },
            )
        )
        return FfnKind.CONFLICT
    if dense_complete:
        return FfnKind.DENSE
    if moe_evidence:
        return FfnKind.MOE
    if state.moe_namespace_present:
        diagnostics.append(
            Diagnostic(
                code="PARTIAL_MOE_SIGNATURE",
                severity=Severity.WARNING,
                message=f"layer {layer_id} has MoE namespace evidence but no routed experts",
                evidence={
                    "layer_id": layer_id,
                    "moe_namespace_present": True,
                    "routed_expert_count": 0,
                },
            )
        )
        return FfnKind.UNKNOWN
    if dense_evidence:
        diagnostics.append(
            Diagnostic(
                code="PARTIAL_DENSE_SIGNATURE",
                severity=Severity.WARNING,
                message=f"layer {layer_id} has an incomplete dense MLP signature",
                evidence={
                    "layer_id": layer_id,
                    "missing_components": json_compatible(
                        sorted(DENSE_COMPONENTS - state.dense_components)
                    ),
                },
            )
        )
    return FfnKind.UNKNOWN


def _model_namespace(name: str) -> str:
    parts = name.split(".")
    if parts[:2] == ["language_model", "model"] and len(parts) >= 3:
        return ".".join(parts[:3])
    if parts and parts[0] == "language_model" and len(parts) >= 2:
        return ".".join(parts[:2])
    return parts[0]


def normalize_inventory(path: Path) -> ModelInventory:
    """Read and compact the top-level raw JSON array."""
    layers: dict[int, _LayerState] = defaultdict(_LayerState)
    dtypes: Counter[str] = Counter()
    shards: set[str] = set()
    model_residuals: set[str] = set()
    exact_names: set[str] = set()
    g_proj_descriptors = _DescriptorAccumulator()
    shared_descriptors: dict[str, _DescriptorAccumulator] = defaultdict(_DescriptorAccumulator)
    residual_descriptors: dict[str, _DescriptorAccumulator] = defaultdict(_DescriptorAccumulator)
    expert_descriptors: dict[str, _DescriptorAccumulator] = defaultdict(_DescriptorAccumulator)
    model_residual_descriptors: dict[str, _DescriptorAccumulator] = defaultdict(
        _DescriptorAccumulator
    )
    unknown_layer_local = _UnclassifiedAccumulator()
    unknown_model = _UnclassifiedAccumulator()
    record_count = 0
    classified_count = 0

    for index, raw_record in enumerate(iter_raw_records(path)):
        record = _validate_record(raw_record, index)
        record_count += 1
        name = record["name"]
        if name in exact_names:
            raise OmivInputError(f"duplicate exact tensor name at record {index}: {name}")
        exact_names.add(name)
        dtypes[record["dtype"]] += 1
        shards.add(record["shard"])
        dtype = record["dtype"]
        shape = tuple(record["shape"])

        layer_match = LAYER_RE.match(name)
        if layer_match:
            layers[int(layer_match.group(1))]

        match = EXPERT_RE.match(name)
        if match:
            layer_id, expert_id = int(match.group(1)), int(match.group(2))
            state = layers[layer_id]
            state.moe_namespace_present = True
            component = f"{match.group(3)}.{match.group(4)}"
            state.experts[expert_id].add(component)
            expert_descriptors[component].observe(
                dtype, shape, layer_id=layer_id, expert_id=expert_id
            )
            classified_count += 1
            continue
        match = DENSE_RE.match(name)
        if match:
            layers[int(match.group(1))].dense_components.add(f"{match.group(2)}.weight")
            classified_count += 1
            continue
        match = SHARED_RE.match(name)
        if match:
            layer_id = int(match.group(1))
            state = layers[layer_id]
            state.moe_namespace_present = True
            component = match.group(2)
            state.shared_components.add(component)
            shared_descriptors[component].observe(dtype, shape, layer_id=layer_id)
            classified_count += 1
            continue
        match = MOE_NAMESPACE_RE.match(name)
        if match:
            layers[int(match.group(1))].moe_namespace_present = True
            classified_count += 1
            continue
        match = SELF_ATTN_RE.match(name)
        if match:
            layer_id = int(match.group(1))
            state = layers[layer_id]
            suffix = match.group(2)
            if suffix == "g_proj.weight":
                state.g_proj_observation_count += 1
                g_proj_descriptors.observe(dtype, shape, layer_id=layer_id)
                classified_count += 1
                continue
            if suffix in KDA_MARKERS or suffix in MLA_MARKERS:
                state.attention_markers.add(suffix)
                classified_count += 1
                continue
        match = LAYER_RESIDUAL_RE.match(name)
        if match:
            layer_id = int(match.group(1))
            component = match.group(2)
            layers[layer_id].residual_components.add(component)
            residual_descriptors[component].observe(dtype, shape, layer_id=layer_id)
            classified_count += 1
            continue
        match = MODEL_RESIDUAL_RE.match(name)
        if match:
            component = match.group(1)
            model_residuals.add(component)
            model_residual_descriptors[component].observe(dtype, shape)
            classified_count += 1
            continue

        if layer_match:
            prefix = layer_match.group(0)
            unknown_layer_local.observe(name[len(prefix) :], name)
        else:
            unknown_model.observe(_model_namespace(name), name)

    diagnostics: list[Diagnostic] = []
    canonical_layers: list[LayerInventory] = []
    for layer_id, state in sorted(layers.items()):
        incomplete: dict[str, list[str]] = {}
        complete_count = 0
        for expert_id, present in sorted(state.experts.items()):
            missing = sorted(str(component) for component in PHASE1_EXPERT_COMPONENT_SET - present)
            if missing:
                incomplete[str(expert_id)] = missing
            else:
                complete_count += 1
        canonical_layers.append(
            LayerInventory(
                id=layer_id,
                attention=AttentionInventory(
                    kind=_classify_attention(layer_id, state, diagnostics),
                    observed_markers=sorted(state.attention_markers),
                    g_proj_present=state.g_proj_observation_count > 0,
                    g_proj_observation_count=state.g_proj_observation_count,
                ),
                ffn=FfnInventory(
                    kind=_classify_ffn(layer_id, state, diagnostics),
                    dense_components=sorted(state.dense_components),
                    routed_expert_ids=sorted(state.experts),
                    expert_component_coverage=ExpertCoverage(
                        complete_expert_count=complete_count,
                        incomplete_experts=incomplete,
                    ),
                    shared_expert_components=sorted(state.shared_components),
                ),
                attention_residual_components=sorted(state.residual_components),
            )
        )
        if incomplete:
            diagnostics.append(
                Diagnostic(
                    code="INCOMPLETE_EXPERT_COMPONENTS",
                    severity=Severity.ERROR,
                    message=f"layer {layer_id} has incomplete routed experts",
                    evidence={
                        "layer_id": layer_id,
                        "incomplete_expert_count": len(incomplete),
                        "incomplete_expert_ids": json_compatible(
                            [int(value) for value in incomplete]
                        ),
                    },
                )
            )

    return ModelInventory(
        schema_version=2,
        source=SourceSummary(
            format="safetensors-header-inventory",
            record_count=record_count,
            source_sha256=_sha256(path),
            shard_count=len(shards),
            shards=sorted(shards),
            dtype_counts=dict(sorted(dtypes.items())),
        ),
        observed_layer_ids=sorted(layers),
        layers=canonical_layers,
        model_attention_residual_components=sorted(model_residuals),
        semantic_descriptors=SemanticDescriptorInventory(
            g_proj=g_proj_descriptors.summary(),
            shared_expert_components={
                component: accumulator.summary()
                for component, accumulator in sorted(shared_descriptors.items())
            },
            attention_residual_components={
                component: accumulator.summary()
                for component, accumulator in sorted(residual_descriptors.items())
            },
            routed_expert_components={
                component: accumulator.summary()
                for component, accumulator in sorted(expert_descriptors.items())
            },
            model_attention_residual_components={
                component: accumulator.summary()
                for component, accumulator in sorted(model_residual_descriptors.items())
            },
        ),
        tensor_classification=TensorClassificationSummary(
            total_tensor_records=record_count,
            semantically_classified_records=classified_count,
            unclassified_records=record_count - classified_count,
            duplicate_exact_tensor_names=0,
            duplicate_examples=[],
            group_cap=UNCLASSIFIED_GROUP_CAP,
            examples_per_group_cap=UNCLASSIFIED_EXAMPLES_PER_GROUP_CAP,
            unknown_layer_local=unknown_layer_local.compact(),
            unknown_model_namespaces=unknown_model.compact(),
        ),
        diagnostics=diagnostics,
    )


def write_inventory(inventory: ModelInventory, path: Path) -> None:
    """Write deterministic, stable canonical JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(inventory.model_dump(mode="json"), indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")
