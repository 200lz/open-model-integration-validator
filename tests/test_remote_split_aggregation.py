from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.remote.header_models import (
    HeaderInventoryEnvelope,
    RemoteTensorDescriptor,
)
from omiv.remote.header_reporting import build_header_inventory_envelope
from omiv.remote.models import (
    RemoteFile,
    RepositoryIdentity,
    RepositoryMetadata,
    RepositorySnapshot,
    SnapshotSelection,
    SnapshotSummary,
    StorageClass,
)
from omiv.remote.reporting import snapshot_envelope
from omiv.remote.split import detect_split_candidates
from omiv.remote.split_aggregation import (
    aggregate_split_inventories,
    compute_payload_span,
    default_ggml_type_policy,
    validate_reusable_inventory,
)
from omiv.remote.split_models import SplitAggregationLimits, SplitMetadataPolicy
from omiv.remote.split_reporting import (
    build_split_inventory_envelope,
    build_split_report,
    load_split_inventory,
    load_split_report,
    pretty_split_json,
    render_split_markdown,
    split_inventory_integrity_matches,
    split_report_integrity_matches,
)
from tests.remote_gguf_helpers import (
    build_gguf,
    metadata_entry,
    parse_fixture,
    tensor_descriptor,
)


def split_metadata(index: int, *, count: int = 3, tensors: int = 2) -> list[bytes]:
    return [
        metadata_entry("split.no", "UINT16", index),
        metadata_entry("split.count", "UINT16", count),
        metadata_entry("split.tensors.count", "INT32", tensors),
        metadata_entry("general.alignment", "UINT32", 32),
    ]


def split_fixture(
    *,
    second_name: str = "a.weight",
    second_type: int = 0,
    second_offset: int = 0,
) -> tuple[object, list[HeaderInventoryEnvelope]]:
    paths = [
        f"q/model-{ordinal:05d}-of-00003.gguf" for ordinal in range(1, 4)
    ]
    binaries = [
        build_gguf(
            metadata=split_metadata(0)
            + [
                metadata_entry("general.architecture", "STRING", "synthetic"),
                metadata_entry(
                    "tokenizer.ggml.tokens",
                    "ARRAY",
                    ("STRING", ["one", "two"]),
                ),
            ],
            payload_bytes=0,
        )[0],
        build_gguf(
            metadata=split_metadata(1),
            tensors=[tensor_descriptor(second_name, [4], second_type, second_offset)],
            payload_bytes=64,
        )[0],
        build_gguf(
            metadata=split_metadata(2),
            tensors=[tensor_descriptor("b.weight", [256], 29, 0)],
            payload_bytes=64,
        )[0],
    ]
    files = [
        RemoteFile(
            path=path,
            byte_size=len(data),
            storage=StorageClass.LFS,
            lfs_sha256=f"{index + 1:064x}",
        )
        for index, (path, data) in enumerate(zip(paths, binaries, strict=True))
    ]
    candidates, extras = detect_split_candidates(paths)
    repository = RepositoryIdentity(
        repo_id="owner/repo",
        repo_type="model",
        requested_revision="main",
        resolved_revision="a" * 40,
    )
    snapshot = snapshot_envelope(
        RepositorySnapshot(
            snapshot_schema="omiv.remote-repository-snapshot.v1",
            provider="huggingface",
            repository=repository,
            repository_metadata=RepositoryMetadata(private=False),
            selection=SnapshotSelection(
                path_prefix="q", patterns=["*.gguf"], strict_subtree=True
            ),
            files=files,
            summary=SnapshotSummary(
                file_count=3,
                total_byte_size=sum(item.byte_size for item in files),
                gguf_file_count=3,
                candidate_split_sets=candidates,
                extra_gguf_files=extras,
            ),
        )
    )
    envelopes = []
    for data, file in zip(binaries, files, strict=True):
        parsed = parse_fixture(data).inventory
        raw = parsed.model_dump(mode="json")
        raw.update(
            repository=repository.model_dump(mode="json"),
            snapshot_sha256=snapshot.integrity.sha256,
            file=file.model_dump(mode="json"),
        )
        envelopes.append(
            build_header_inventory_envelope(type(parsed).model_validate(raw))
        )
    return snapshot, envelopes


def test_valid_split_normalization_metadata_and_tensor_aggregation() -> None:
    snapshot, inventories = split_fixture()
    result = aggregate_split_inventories(
        snapshot, inventories, reused_inventory_count=1
    )
    assert result.shard_count == 3
    assert [item.header_split_index for item in result.split_identities] == [0, 1, 2]
    assert [item.normalized_header_ordinal for item in result.split_identities] == [1, 2, 3]
    assert all(item.agrees for item in result.split_identities)
    assert result.global_tensor_count_metadata == result.aggregated_tensor_count == 2
    assert [item.name for item in result.tensors] == ["a.weight", "b.weight"]
    assert result.metadata_consistency.broadest_metadata_shard.endswith("00001-of-00003.gguf")
    assert "tokenizer.ggml.tokens" in result.metadata_consistency.primary_only_keys
    assert result.payload_span_summary.bounded_count == 2
    assert result.payload_span_summary.overlap_count == 0
    assert result.reused_inventory_count == 1
    assert result.remotely_parsed_inventory_count == 2
    assert all(item.status.value == "pass" for item in result.findings)


def test_inventory_reuse_rejects_foreign_linkage_and_policy() -> None:
    snapshot, inventories = split_fixture()
    item = inventories[0]
    validate_reusable_inventory(
        item,
        snapshot=snapshot,
        expected_path=item.inventory.file.path,
        expected_policy_sha256=item.inventory.parser_policy_sha256,
    )
    raw = item.model_dump(mode="json")
    raw["inventory"]["snapshot_sha256"] = "f" * 64
    foreign = HeaderInventoryEnvelope.model_validate(raw)
    with pytest.raises(OmivInputError, match="integrity"):
        validate_reusable_inventory(
            foreign,
            snapshot=snapshot,
            expected_path=item.inventory.file.path,
            expected_policy_sha256=item.inventory.parser_policy_sha256,
        )
    with pytest.raises(OmivInputError, match="policy"):
        validate_reusable_inventory(
            item,
            snapshot=snapshot,
            expected_path=item.inventory.file.path,
            expected_policy_sha256="f" * 64,
        )


def test_missing_and_malformed_split_evidence_fails() -> None:
    snapshot, inventories = split_fixture()
    with pytest.raises(OmivInputError, match="not all selected"):
        aggregate_split_inventories(
            snapshot, inventories[:-1], reused_inventory_count=0
        )

    raw = inventories[1].inventory.model_dump(mode="json")
    raw["metadata"] = [
        item for item in raw["metadata"] if item["key"] != "split.no"
    ]
    raw["metadata_count"] -= 1
    raw["summary"]["metadata_type_counts"]["UINT16"] -= 1
    raw["summary"]["largest_metadata_entries"] = [
        item
        for item in raw["summary"]["largest_metadata_entries"]
        if item["key"] != "split.no"
    ]
    malformed = type(inventories[1].inventory).model_validate(raw)
    modified = list(inventories)
    modified[1] = build_header_inventory_envelope(malformed)
    with pytest.raises(OmivInputError, match="absent"):
        aggregate_split_inventories(snapshot, modified, reused_inventory_count=0)


def test_duplicate_tensor_and_metadata_conflict_are_failures() -> None:
    snapshot, inventories = split_fixture(second_name="b.weight")
    result = aggregate_split_inventories(
        snapshot, inventories, reused_inventory_count=0
    )
    assert result.duplicate_summary.conflict_count == 1
    duplicate_finding = next(
        item for item in result.findings if item.rule_id == "SPLIT-008"
    )
    assert duplicate_finding.status.value == "fail"

    raw = inventories[2].inventory.model_dump(mode="json")
    alignment = next(
        item for item in raw["metadata"] if item["key"] == "general.alignment"
    )
    alignment["encoded_sha256"] = "f" * 64
    changed = type(inventories[2].inventory).model_validate(raw)
    modified = [inventories[0], inventories[1], build_header_inventory_envelope(changed)]
    result = aggregate_split_inventories(
        snapshot, modified, reused_inventory_count=0
    )
    assert "general.alignment" in result.metadata_consistency.required_equal_failures


def test_type_traits_spans_boundaries_unsupported_and_overflow() -> None:
    policy = default_ggml_type_policy()
    f32 = RemoteTensorDescriptor(
        name="f32",
        dimensions=[4, 2],
        ggml_type_code=0,
        ggml_type_name="F32",
        data_offset=0,
        logical_element_count=8,
        encoded_start=24,
        encoded_end=64,
        encoded_byte_length=40,
        encoded_sha256="a" * 64,
    )
    span = compute_payload_span(f32, payload_start=32, file_size=64, type_policy=policy)
    assert span.status == "bounded" and span.absolute_end == 64
    iq1 = f32.model_copy(
        update={
            "name": "iq1",
            "dimensions": [256],
            "ggml_type_code": 29,
            "ggml_type_name": "IQ1_M",
            "logical_element_count": 256,
        }
    )
    assert compute_payload_span(
        iq1, payload_start=32, file_size=88, type_policy=policy
    ).encoded_byte_length == 56
    invalid = iq1.model_copy(update={"dimensions": [255]})
    assert compute_payload_span(
        invalid, payload_start=0, file_size=100, type_policy=policy
    ).status == "invalid"
    unknown = iq1.model_copy(update={"ggml_type_code": 999, "ggml_type_name": "X"})
    assert compute_payload_span(
        unknown, payload_start=0, file_size=100, type_policy=policy
    ).status == "unsupported"
    with pytest.raises(OmivInputError, match="overflows"):
        compute_payload_span(
            iq1.model_copy(update={"data_offset": (1 << 64) - 1}),
            payload_start=1,
            file_size=(1 << 64) - 1,
            type_policy=policy,
        )


@pytest.mark.parametrize(
    "limits",
    [
        SplitAggregationLimits(max_shard_count=2),
        SplitAggregationLimits(max_total_header_bytes=24),
        SplitAggregationLimits(max_total_request_count=1),
        SplitAggregationLimits(max_total_metadata_records=1),
        SplitAggregationLimits(max_total_tensor_descriptors=1),
    ],
)
def test_aggregate_limits(limits: SplitAggregationLimits) -> None:
    snapshot, inventories = split_fixture()
    with pytest.raises(OmivInputError, match="exceed"):
        aggregate_split_inventories(
            snapshot, inventories, reused_inventory_count=0, limits=limits
        )


def test_split_inventory_report_integrity_markdown_and_tamper(tmp_path: Path) -> None:
    snapshot, inventories = split_fixture()
    inventory = build_split_inventory_envelope(
        aggregate_split_inventories(
            snapshot, inventories, reused_inventory_count=3
        )
    )
    report = build_split_report(inventory)
    assert split_inventory_integrity_matches(inventory)
    assert split_report_integrity_matches(report)
    assert pretty_split_json(report) == pretty_split_json(build_split_report(inventory))
    markdown = render_split_markdown(report)
    assert "SPLIT\\-009" in markdown
    encoded = pretty_split_json(report)
    for forbidden in (
        "https://",
        "Authorization",
        "Bearer ",
        "X-Amz-",
        "/home/",
        "timestamp",
    ):
        assert forbidden not in encoded
    inventory_path = tmp_path / "split.inventory.json"
    report_path = tmp_path / "split.report.json"
    inventory_path.write_text(pretty_split_json(inventory), encoding="utf-8")
    report_path.write_text(encoded, encoding="utf-8")
    assert split_inventory_integrity_matches(load_split_inventory(inventory_path))
    assert split_report_integrity_matches(load_split_report(report_path))
    runner = CliRunner()
    assert runner.invoke(
        app,
        ["remote-split-inventory-verify", "--input", str(inventory_path)],
    ).exit_code == 0
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 0
    raw = json.loads(encoded)
    raw["integrity"]["sha256"] = "f" * 64
    report_path.write_text(json.dumps(raw), encoding="utf-8")
    assert not split_report_integrity_matches(load_split_report(report_path))


def test_policy_digests_are_deterministic() -> None:
    assert SplitMetadataPolicy().digest == SplitMetadataPolicy().digest
    assert default_ggml_type_policy().digest == default_ggml_type_policy().digest
    assert SplitAggregationLimits().digest == SplitAggregationLimits().digest
