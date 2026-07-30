"""Deterministic structural aggregation of independent split GGUF inventories."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Literal

from pydantic import JsonValue

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.errors import OmivInputError
from omiv.remote.header_models import (
    HeaderInventoryEnvelope,
    MetadataValueType,
    RemoteGGUFHeaderInventory,
    RemoteMetadataEntry,
    RemoteTensorDescriptor,
)
from omiv.remote.models import (
    RemoteFinding,
    RemoteResult,
    RemoteSeverity,
    SnapshotEnvelope,
)
from omiv.remote.split_models import (
    DuplicateSummary,
    GGMLTypePolicyAny,
    GGMLTypePolicyV2,
    GGMLTypeTraitV2,
    GlobalTensorDescriptor,
    MetadataConsistencyClass,
    MetadataConsistencySummary,
    PayloadSpan,
    PayloadSpanSummary,
    SplitAggregationLimits,
    SplitGGUFInventory,
    SplitIdentity,
    SplitMetadataPolicy,
    SplitShardSummary,
)

MAX_U64 = (1 << 64) - 1
_SHARD_NAME = re.compile(
    r"^.+-(?P<ordinal>[0-9]{5})-of-(?P<count>[0-9]{5})\.gguf$",
    re.IGNORECASE,
)
SPLIT_NO = "split.no"
SPLIT_COUNT = "split.count"
SPLIT_TENSOR_COUNT = "split.tensors.count"


def default_ggml_type_policy() -> GGMLTypePolicyV2:
    # Block sizes and encoded sizes are transcribed from ggml type_traits and
    # static assertions at the recorded llama.cpp source identity.
    values = {
        0: ("F32", 1, 4),
        1: ("F16", 1, 2),
        2: ("Q4_0", 32, 18),
        3: ("Q4_1", 32, 20),
        6: ("Q5_0", 32, 22),
        7: ("Q5_1", 32, 24),
        8: ("Q8_0", 32, 34),
        9: ("Q8_1", 32, 36),
        10: ("Q2_K", 256, 84),
        11: ("Q3_K", 256, 110),
        12: ("Q4_K", 256, 144),
        13: ("Q5_K", 256, 176),
        14: ("Q6_K", 256, 210),
        15: ("Q8_K", 256, 292),
        16: ("IQ2_XXS", 256, 66),
        17: ("IQ2_XS", 256, 74),
        18: ("IQ3_XXS", 256, 98),
        19: ("IQ1_S", 256, 50),
        20: ("IQ4_NL", 32, 18),
        21: ("IQ3_S", 256, 110),
        22: ("IQ2_S", 256, 82),
        23: ("IQ4_XS", 256, 136),
        24: ("I8", 1, 1),
        25: ("I16", 1, 2),
        26: ("I32", 1, 4),
        27: ("I64", 1, 8),
        28: ("F64", 1, 8),
        29: ("IQ1_M", 256, 56),
        30: ("BF16", 1, 2),
        34: ("TQ1_0", 256, 54),
        35: ("TQ2_0", 256, 66),
    }
    traits = [
        GGMLTypeTraitV2(
            type_code=code,
            type_name=name,
            block_elements=block,
            block_bytes=size,
        )
        for code, (name, block, size) in sorted(values.items())
    ]
    traits.append(
        GGMLTypeTraitV2(
            type_code=39,
            type_name="MXFP4",
            block_elements=32,
            block_bytes=17,
            layout_rule="GGUF row dimension ne[0] must be divisible by QK_MXFP4=32",
            encoded_size_formula=(
                "(ne[0] / 32) * 17 * product(ne[1:]); checked unsigned-64 arithmetic"
            ),
            evidence_role=(
                "ggml/include/ggml.h enum; ggml/src/ggml-common.h block_mxfp4; "
                "ggml/src/ggml.c type_traits and ggml_row_size"
            ),
        )
    )
    return GGMLTypePolicyV2(
        policy_schema="omiv.ggml-type-size-policy.v2",
        source_identity="llama.cpp@cf67f0d24511864d2d3da0769108fd6fc16d00d1",
        evidence_revision="cf67f0d24511864d2d3da0769108fd6fc16d00d1",
        evidence_role=(
            "GGML enum, canonical block traits, static layout assertions, row-size formula"
        ),
        traits=sorted(traits, key=lambda item: item.type_code),
    )


def validate_reusable_inventory(
    envelope: HeaderInventoryEnvelope,
    *,
    snapshot: SnapshotEnvelope,
    expected_path: str,
    expected_policy_sha256: str | None,
) -> None:
    inventory = envelope.inventory
    files = {item.path: item for item in snapshot.snapshot.files}
    file = files.get(expected_path)
    if file is None:
        raise OmivInputError("reusable inventory file is not selected by snapshot")
    if envelope.integrity.sha256 != canonical_sha256(inventory.model_dump(mode="json")):
        raise OmivInputError("reusable header inventory integrity mismatch")
    if inventory.snapshot_sha256 != snapshot.integrity.sha256:
        raise OmivInputError("reusable header inventory snapshot linkage mismatch")
    if inventory.repository != snapshot.snapshot.repository:
        raise OmivInputError("reusable header inventory repository or revision mismatch")
    if inventory.file != file:
        raise OmivInputError("reusable header inventory file identity mismatch")
    if expected_policy_sha256 is not None and (
        inventory.parser_policy_sha256 != expected_policy_sha256
    ):
        raise OmivInputError("reusable header inventory parser policy mismatch")


def _metadata_map(inventory: RemoteGGUFHeaderInventory) -> dict[str, RemoteMetadataEntry]:
    return {item.key: item for item in inventory.metadata}


def _integer_metadata(
    inventory: RemoteGGUFHeaderInventory,
    key: str,
    *,
    allowed_types: set[MetadataValueType],
) -> int:
    entry = _metadata_map(inventory).get(key)
    if entry is None:
        raise OmivInputError(f"required GGUF split metadata is absent: {key}")
    if entry.value_type not in allowed_types:
        raise OmivInputError(f"GGUF split metadata has invalid type: {key}")
    value = entry.summary_value
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OmivInputError(f"GGUF split metadata has invalid value: {key}")
    return value


def _checked_multiply(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or (left and right > MAX_U64 // left):
        raise OmivInputError(f"{label} overflows unsigned 64-bit arithmetic")
    return left * right


def _checked_add(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or right > MAX_U64 - left:
        raise OmivInputError(f"{label} overflows unsigned 64-bit arithmetic")
    return left + right


def compute_payload_span(
    tensor: RemoteTensorDescriptor,
    *,
    payload_start: int,
    file_size: int,
    type_policy: GGMLTypePolicyAny,
) -> PayloadSpan:
    if not tensor.dimensions or any(dimension <= 0 for dimension in tensor.dimensions):
        return PayloadSpan(
            status="invalid",
            absolute_start=payload_start,
            reason="logical tensor dimensions must be nonzero",
        )
    absolute_start = _checked_add(
        payload_start, tensor.data_offset, f"tensor {tensor.name!r} absolute offset"
    )
    if absolute_start > file_size:
        return PayloadSpan(
            status="invalid",
            absolute_start=absolute_start,
            reason="tensor starts beyond repository-declared file size",
        )
    traits = {item.type_code: item for item in type_policy.traits}
    trait = traits.get(tensor.ggml_type_code)
    if trait is None:
        return PayloadSpan(
            status="unsupported",
            absolute_start=absolute_start,
            reason="GGML encoded-size trait is not recorded",
        )
    row_elements = tensor.dimensions[0]
    if row_elements % trait.block_elements:
        return PayloadSpan(
            status="invalid",
            absolute_start=absolute_start,
            reason="GGUF row dimension is not divisible by the GGML block size",
        )
    row_blocks = row_elements // trait.block_elements
    row_bytes = _checked_multiply(row_blocks, trait.block_bytes, "GGML row byte size")
    row_count = 1
    for dimension in tensor.dimensions[1:]:
        row_count = _checked_multiply(row_count, dimension, "GGML tensor row count")
    encoded_length = _checked_multiply(row_bytes, row_count, "GGML tensor byte size")
    if encoded_length == 0:
        return PayloadSpan(
            status="invalid",
            absolute_start=absolute_start,
            reason="zero-sized tensor encoding",
        )
    absolute_end = _checked_add(absolute_start, encoded_length, "tensor payload end")
    return PayloadSpan(
        status="bounded" if absolute_end <= file_size else "invalid",
        absolute_start=absolute_start,
        absolute_end=absolute_end,
        encoded_byte_length=encoded_length,
        reason=None if absolute_end <= file_size else "tensor ends beyond file size",
    )


def _finding(
    rule: str,
    status: RemoteResult,
    message: str,
    **evidence: JsonValue,
) -> RemoteFinding:
    severity = (
        RemoteSeverity.ERROR
        if status == RemoteResult.FAIL
        else RemoteSeverity.WARNING
        if status == RemoteResult.WARN
        else RemoteSeverity.INFO
    )
    return RemoteFinding(
        rule_id=rule,
        severity=severity,
        status=status,
        message=message,
        evidence=evidence,
    )


def aggregate_split_inventories(
    snapshot: SnapshotEnvelope,
    inventories: Sequence[HeaderInventoryEnvelope],
    *,
    reused_inventory_count: int,
    limits: SplitAggregationLimits | None = None,
    metadata_policy: SplitMetadataPolicy | None = None,
    type_policy: GGMLTypePolicyAny | None = None,
) -> SplitGGUFInventory:
    selected_limits = limits or SplitAggregationLimits()
    selected_metadata_policy = metadata_policy or SplitMetadataPolicy()
    selected_type_policy = type_policy or default_ggml_type_policy()
    candidates = snapshot.snapshot.summary.candidate_split_sets
    if len(candidates) != 1 or not candidates[0].complete:
        raise OmivInputError("snapshot must contain exactly one complete split candidate")
    candidate = candidates[0]
    if snapshot.snapshot.summary.extra_gguf_files:
        raise OmivInputError("snapshot selection contains unrelated GGUF files")
    if len(inventories) != len(candidate.files):
        raise OmivInputError("not all selected split shards were supplied")
    if len(inventories) > selected_limits.max_shard_count:
        raise OmivInputError("split shard count exceeds aggregation policy")

    by_path = {item.inventory.file.path: item for item in inventories}
    if len(by_path) != len(inventories) or set(by_path) != set(candidate.files):
        raise OmivInputError("split inventory paths do not exactly match candidate files")
    ordered: list[tuple[int, int, HeaderInventoryEnvelope]] = []
    for path in candidate.files:
        match = _SHARD_NAME.fullmatch(path.rsplit("/", 1)[-1])
        if match is None:
            raise OmivInputError("candidate path no longer matches split filename grammar")
        ordered.append((int(match.group("ordinal")), int(match.group("count")), by_path[path]))
    ordered.sort(key=lambda item: item[0])
    parser_digests = {item.inventory.parser_policy_sha256 for _, _, item in ordered}
    if len(parser_digests) != 1:
        raise OmivInputError("cannot mix per-shard parser policies")
    for _, _, envelope in ordered:
        validate_reusable_inventory(
            envelope,
            snapshot=snapshot,
            expected_path=envelope.inventory.file.path,
            expected_policy_sha256=next(iter(parser_digests)),
        )

    total_header = sum(item.inventory.total_remote_bytes_accepted for _, _, item in ordered)
    total_requests = sum(item.inventory.request_count for _, _, item in ordered)
    total_metadata = sum(item.inventory.metadata_count for _, _, item in ordered)
    total_tensors = sum(item.inventory.tensor_count for _, _, item in ordered)
    if total_header > selected_limits.max_total_header_bytes:
        raise OmivInputError("total accepted header bytes exceed aggregation policy")
    if total_requests > selected_limits.max_total_request_count:
        raise OmivInputError("total Range request count exceeds aggregation policy")
    if total_metadata > selected_limits.max_total_metadata_records:
        raise OmivInputError("total metadata records exceed aggregation policy")
    if total_tensors > selected_limits.max_total_tensor_descriptors:
        raise OmivInputError("total tensor descriptors exceed aggregation policy")

    identities: list[SplitIdentity] = []
    split_indices: list[int] = []
    split_counts: list[int] = []
    global_counts: list[int] = []
    for ordinal, declared, envelope in ordered:
        inv = envelope.inventory
        split_index = _integer_metadata(
            inv, SPLIT_NO, allowed_types={MetadataValueType.UINT16, MetadataValueType.UINT32}
        )
        split_count = _integer_metadata(
            inv,
            SPLIT_COUNT,
            allowed_types={MetadataValueType.UINT16, MetadataValueType.UINT32},
        )
        global_count = _integer_metadata(
            inv,
            SPLIT_TENSOR_COUNT,
            allowed_types={MetadataValueType.INT32, MetadataValueType.UINT32},
        )
        normalized = split_index + 1
        agrees = normalized == ordinal and split_count == declared
        identities.append(
            SplitIdentity(
                filename_ordinal=ordinal,
                filename_declared_count=declared,
                header_split_index=split_index,
                normalized_header_ordinal=normalized,
                header_split_count=split_count,
                global_tensor_count=global_count,
                agrees=agrees,
            )
        )
        split_indices.append(split_index)
        split_counts.append(split_count)
        global_counts.append(global_count)

    expected_indices = list(range(len(ordered)))
    header_indices_complete = sorted(split_indices) == expected_indices
    identity_agreement = all(item.agrees for item in identities)
    counts_agree = (
        len(set(split_counts)) == 1
        and split_counts[0] == candidate.declared_shard_count
        and len(ordered) == split_counts[0]
    )
    global_count_agrees = len(set(global_counts)) == 1 and global_counts[0] == total_tensors

    metadata_maps = [_metadata_map(item.inventory) for _, _, item in ordered]
    all_keys = sorted(set().union(*(set(item) for item in metadata_maps)))
    broadest_index = max(range(len(ordered)), key=lambda index: (len(metadata_maps[index]), -index))
    broadest_path = ordered[broadest_index][2].inventory.file.path
    replicated = [key for key in all_keys if all(key in item for item in metadata_maps)]
    primary_only = [
        key for key in all_keys if sum(key in item for item in metadata_maps) == 1
    ]
    class_counts: Counter[str] = Counter()
    required_equal_failures: list[str] = []
    required_equal_checked = 0
    for key in all_keys:
        classification = selected_metadata_policy.classify(key)
        class_counts[classification.value] += 1
        present = [item[key] for item in metadata_maps if key in item]
        if classification == MetadataConsistencyClass.REQUIRED_PRESENT_ALL:
            if len(present) != len(metadata_maps):
                required_equal_failures.append(key)
        elif classification == MetadataConsistencyClass.REQUIRED_EQUAL:
            required_equal_checked += 1
            digests = {item.encoded_sha256 for item in present}
            if len(present) != len(metadata_maps) or len(digests) != 1:
                required_equal_failures.append(key)
        elif classification == MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY:
            if len(present) not in {1, len(metadata_maps)}:
                required_equal_failures.append(key)
            if len(present) == len(metadata_maps) and len(
                {item.encoded_sha256 for item in present}
            ) != 1:
                required_equal_failures.append(key)
    if len({item.inventory.alignment for _, _, item in ordered}) != 1:
        required_equal_failures.append("<effective-alignment>")
    required_equal_failures = sorted(set(required_equal_failures))

    tensors: list[GlobalTensorDescriptor] = []
    spans_by_shard: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for (ordinal, _, envelope), identity in zip(ordered, identities, strict=True):
        inv = envelope.inventory
        for descriptor_index, remote_tensor in enumerate(inv.tensors):
            span = compute_payload_span(
                remote_tensor,
                payload_start=inv.payload_start_offset,
                file_size=inv.file.byte_size,
                type_policy=selected_type_policy,
            )
            tensors.append(
                GlobalTensorDescriptor(
                    name=remote_tensor.name,
                    shard_path=inv.file.path,
                    filename_ordinal=ordinal,
                    header_split_index=identity.header_split_index,
                    descriptor_index=descriptor_index,
                    dimensions=remote_tensor.dimensions,
                    ggml_type_code=remote_tensor.ggml_type_code,
                    ggml_type_name=remote_tensor.ggml_type_name,
                    relative_data_offset=remote_tensor.data_offset,
                    descriptor_sha256=remote_tensor.encoded_sha256,
                    payload_span=span,
                )
            )
            if span.status == "bounded" and span.absolute_end is not None:
                spans_by_shard[inv.file.path].append(
                    (span.absolute_start, span.absolute_end, remote_tensor.name)
                )
    tensors.sort(key=lambda item: (item.name, item.filename_ordinal, item.descriptor_index))

    names: dict[str, list[GlobalTensorDescriptor]] = defaultdict(list)
    for tensor in tensors:
        names[tensor.name].append(tensor)
    exact: list[str] = []
    conflicts: list[str] = []
    duplicate_details: list[dict[str, object]] = []
    for name in sorted(key for key, values in names.items() if len(values) > 1):
        values = names[name]
        identities_for_name = {
            (
                tuple(item.dimensions),
                item.ggml_type_code,
                item.relative_data_offset,
                item.descriptor_sha256,
            )
            for item in values
        }
        target = exact if len(identities_for_name) == 1 else conflicts
        target.append(name)
        duplicate_details.append(
            {
                "name": name,
                "kind": "exact" if target is exact else "conflict",
                "shards": [item.shard_path for item in values],
            }
        )
    retained_exact = exact[: selected_limits.max_duplicate_details]
    retained_conflicts = conflicts[: selected_limits.max_duplicate_details]
    duplicates = DuplicateSummary(
        exact_duplicate_count=len(exact),
        conflict_count=len(conflicts),
        exact_duplicate_names=retained_exact,
        conflicting_names=retained_conflicts,
        detail_digest=canonical_sha256(duplicate_details),
    )

    overlap_count = 0
    for shard_spans in spans_by_shard.values():
        shard_spans.sort()
        for previous, current in zip(shard_spans, shard_spans[1:], strict=False):
            if current[0] < previous[1]:
                overlap_count += 1
    supported_counts = Counter(
        item.ggml_type_name for item in tensors if item.payload_span.status != "unsupported"
    )
    unsupported_counts = Counter(
        item.ggml_type_name for item in tensors if item.payload_span.status == "unsupported"
    )
    span_summary = PayloadSpanSummary(
        computable_count=sum(item.payload_span.status != "unsupported" for item in tensors),
        bounded_count=sum(item.payload_span.status == "bounded" for item in tensors),
        unsupported_count=sum(item.payload_span.status == "unsupported" for item in tensors),
        invalid_count=sum(item.payload_span.status == "invalid" for item in tensors),
        overlap_count=overlap_count,
        supported_type_counts=dict(sorted(supported_counts.items())),
        unsupported_type_counts=dict(sorted(unsupported_counts.items())),
    )

    shard_summaries: list[SplitShardSummary] = []
    for (ordinal, declared, envelope), identity in zip(ordered, identities, strict=True):
        inv = envelope.inventory
        shard_tensors = [item for item in tensors if item.shard_path == inv.file.path]
        result: Literal["bounded", "unsupported", "invalid", "no_tensors"] = (
            "no_tensors"
            if not shard_tensors
            else "invalid"
            if any(item.payload_span.status == "invalid" for item in shard_tensors)
            else "unsupported"
            if any(item.payload_span.status == "unsupported" for item in shard_tensors)
            else "bounded"
        )
        role: Literal["broadest_metadata", "metadata_subset", "metadata_equal"] = (
            "broadest_metadata"
            if inv.file.path == broadest_path
            else "metadata_equal"
            if len(inv.metadata) == len(metadata_maps[broadest_index])
            else "metadata_subset"
        )
        shard_summaries.append(
            SplitShardSummary(
                path=inv.file.path,
                filename_ordinal=ordinal,
                header_split_index=identity.header_split_index,
                declared_split_count=declared,
                file_size=inv.file.byte_size,
                gguf_version=inv.gguf_version,
                metadata_count=inv.metadata_count,
                tensor_count=inv.tensor_count,
                payload_start=inv.payload_start_offset,
                accepted_header_bytes=inv.total_remote_bytes_accepted,
                request_count=inv.request_count,
                inventory_sha256=envelope.integrity.sha256,
                metadata_role=role,
                payload_span_result=result,
            )
        )

    findings = [
        _finding(
            "SPLIT-001",
            RemoteResult.PASS,
            "Filename split set is complete.",
            shard_count=len(ordered),
        ),
        _finding(
            "SPLIT-002",
            RemoteResult.PASS if header_indices_complete else RemoteResult.FAIL,
            "Zero-based header split indices are complete and unique.",
            header_indices_complete=header_indices_complete,
        ),
        _finding(
            "SPLIT-003",
            RemoteResult.PASS if identity_agreement else RemoteResult.FAIL,
            "Filename and normalized header shard identities agree.",
            identity_agreement=identity_agreement,
        ),
        _finding(
            "SPLIT-004",
            RemoteResult.PASS if counts_agree else RemoteResult.FAIL,
            "Filename, header, and selected split counts agree.",
            declared_split_count=candidate.declared_shard_count,
        ),
        _finding(
            "SPLIT-005",
            RemoteResult.PASS if not required_equal_failures else RemoteResult.FAIL,
            "Policy-selected metadata consistency rules were evaluated.",
            failure_count=len(required_equal_failures),
        ),
        _finding(
            "SPLIT-006",
            RemoteResult.PASS if not required_equal_failures else RemoteResult.FAIL,
            "Primary-only and subset metadata follow the recorded policy.",
            primary_only_key_count=len(primary_only),
        ),
        _finding(
            "SPLIT-007",
            RemoteResult.PASS if global_count_agrees else RemoteResult.FAIL,
            "Aggregated descriptor count agrees with split tensor-count metadata.",
            aggregated_tensor_count=total_tensors,
            declared_global_tensor_count=global_counts[0],
        ),
        _finding(
            "SPLIT-008",
            RemoteResult.PASS if not exact and not conflicts else RemoteResult.FAIL,
            "Tensor names are globally unique across shards.",
            exact_duplicate_count=len(exact),
            conflict_count=len(conflicts),
        ),
        _finding(
            "SPLIT-009",
            RemoteResult.FAIL
            if span_summary.invalid_count
            else RemoteResult.WARN
            if span_summary.unsupported_count
            else RemoteResult.PASS,
            "Computable tensor payload spans remain within declared shard bounds.",
            bounded_count=span_summary.bounded_count,
            unsupported_count=span_summary.unsupported_count,
            invalid_count=span_summary.invalid_count,
        ),
        _finding(
            "SPLIT-010",
            RemoteResult.FAIL
            if overlap_count
            else RemoteResult.WARN
            if span_summary.unsupported_count
            else RemoteResult.PASS,
            "No unexpected overlap was found among computable spans.",
            overlap_count=overlap_count,
        ),
        _finding(
            "SPLIT-011",
            RemoteResult.PASS,
            "Every selected filename shard is represented exactly once.",
            selected_shard_count=len(ordered),
        ),
        _finding(
            "SPLIT-012",
            RemoteResult.PASS,
            "Aggregate policies and inventory use deterministic canonical hashing.",
            aggregation_policy_sha256=selected_limits.digest,
        ),
    ]

    metadata_summary = MetadataConsistencySummary(
        broadest_metadata_shard=broadest_path,
        replicated_all_keys=replicated[: selected_limits.max_metadata_summaries],
        primary_only_keys=primary_only[: selected_limits.max_metadata_summaries],
        required_equal_checked=required_equal_checked,
        required_equal_failures=required_equal_failures[
            : selected_limits.max_metadata_summaries
        ],
        policy_class_counts=dict(sorted(class_counts.items())),
    )
    first = ordered[0][2].inventory
    inventory = SplitGGUFInventory(
        provider="huggingface",
        repository=snapshot.snapshot.repository,
        snapshot_sha256=snapshot.integrity.sha256,
        selection=snapshot.snapshot.selection,
        filename_candidate_stem=candidate.stem,
        header_parser_policy=first.parser_policy,
        header_parser_policy_sha256=first.parser_policy_sha256,
        aggregation_policy=selected_limits,
        aggregation_policy_sha256=selected_limits.digest,
        metadata_policy=selected_metadata_policy,
        metadata_policy_sha256=selected_metadata_policy.digest,
        ggml_type_policy=selected_type_policy,
        ggml_type_policy_sha256=selected_type_policy.digest,
        shard_count=len(ordered),
        declared_split_count=candidate.declared_shard_count,
        global_tensor_count_metadata=global_counts[0],
        aggregated_tensor_count=total_tensors,
        total_repository_bytes=sum(item.inventory.file.byte_size for _, _, item in ordered),
        total_header_bytes_accepted=total_header,
        total_request_count=total_requests,
        reused_inventory_count=reused_inventory_count,
        remotely_parsed_inventory_count=len(ordered) - reused_inventory_count,
        shard_summaries=shard_summaries,
        split_identities=identities,
        metadata_consistency=metadata_summary,
        tensors=tensors,
        representative_tensors=tensors[: selected_limits.max_representative_tensors],
        duplicate_summary=duplicates,
        payload_span_summary=span_summary,
        findings=findings,
    )
    serialized_size = len(canonical_json_bytes(inventory.model_dump(mode="json")))
    if serialized_size > selected_limits.max_serialized_inventory_bytes:
        raise OmivInputError("combined split inventory exceeds serialized-size policy")
    return inventory
