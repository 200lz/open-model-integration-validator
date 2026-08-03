"""Practice-profile generation layered outside the provider-neutral core."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from omiv.reconciliation.building import identified
from omiv.reconciliation.examples import generate_reconciliation_examples
from omiv.reconciliation.models import (
    ObjectReference,
    ReconciliationArtifactIndex,
    ReconciliationArtifactIndexEntry,
)
from omiv.reconciliation.reporting import pretty_json
from omiv.reconciliation_profiles.practice import (
    deepseek_profile,
    kimi_profile,
    xai_profile,
)
from omiv.reconciliation_profiles.xai import (
    XaiPinnedMetadataEvidence,
    build_case_study,
    build_xai_practice_objects,
    load_pinned_fixture,
    render_case_study,
)
from omiv.safe_write import atomic_write_text


def generate_all_reconciliation_examples(root: Path) -> ReconciliationArtifactIndex:
    generate_reconciliation_examples(root)
    repository_root = Path(__file__).resolve().parents[3]
    fixture_root = repository_root / "fixtures" / "reconciliation" / "xai"
    xai_fixtures = tuple(
        load_pinned_fixture(fixture_root / f"{repository}.pinned-metadata.json")
        for repository in ("grok-1", "grok-2")
    )
    xai_evidences: list[XaiPinnedMetadataEvidence] = []
    for fixture in xai_fixtures:
        objects = build_xai_practice_objects(fixture)
        base = root / "reconciliation" / "practice" / "xai" / fixture.repository
        for name in (
            "locator",
            "plan",
            "execution",
            "snapshot",
            "topology",
            "completeness",
            "expectation",
            "evidence",
        ):
            atomic_write_text(base / f"{name}.json", pretty_json(objects[name]))
        xai_evidences.append(objects["evidence"])
    xai_report = build_case_study(xai_fixtures, tuple(xai_evidences))
    atomic_write_text(
        root / "reports" / "reconciliation" / "xai-public-metadata-case-study.json",
        pretty_json(xai_report),
    )
    atomic_write_text(
        root / "reports" / "reconciliation" / "xai-public-metadata-case-study.md",
        render_case_study(xai_report),
    )
    prior_path = (
        repository_root
        / "snapshots"
        / "huggingface"
        / "unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.snapshot.json"
    )
    prior_digest = hashlib.sha256(prior_path.read_bytes()).hexdigest()
    prior = ObjectReference(
        schema_id="omiv.remote-repository-snapshot-envelope.v1",
        object_id="legacy_snapshot_" + prior_digest[:32],
        object_digest=prior_digest,
    )
    profiles = {
        "kimi": kimi_profile((prior,)),
        "deepseek": deepseek_profile(),
        "xai": xai_profile(
            tuple(
                ObjectReference(
                    schema_id=item.schema_id,
                    object_id=item.evidence_id,
                    object_digest=item.evidence_digest,
                )
                for item in xai_evidences
            )
        ),
    }
    for name, profile in profiles.items():
        path = root / "reconciliation" / "profiles" / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, pretty_json(profile))
    return _rebuild_index(root)


def _rebuild_index(root: Path) -> ReconciliationArtifactIndex:
    entries: list[ReconciliationArtifactIndexEntry] = []
    identities: set[str] = set()
    contents: set[str] = set()
    for directory in (root / "reconciliation", root / "reports" / "reconciliation"):
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.name == "artifact-index.json":
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".json":
                value = json.loads(data)
                schema = str(value["schema"])
                canonical_id = _canonical_id(value)
            else:
                schema = "omiv.remote-local-reconciliation-report-markdown.v1"
                canonical_id = "reconciliation_markdown_" + digest[:32]
            if canonical_id in identities or digest in contents:
                raise ValueError("duplicate Phase 6B canonical identity or content")
            identities.add(canonical_id)
            contents.add(digest)
            entries.append(
                ReconciliationArtifactIndexEntry(
                    path=relative,
                    size=len(data),
                    sha256=digest,
                    schema_id=schema,
                    canonical_id=canonical_id,
                )
            )
    entries.sort(key=lambda item: item.path.encode())
    body = {
        "schema": "omiv.reconciliation-artifact-index.v1",
        "entries": [item.model_dump(mode="json") for item in entries],
        "total_size": sum(item.size for item in entries),
        "limitations": [
            "External index excludes itself and deterministic artifacts contain no model "
            "payload bytes."
        ],
    }
    index = ReconciliationArtifactIndex.model_validate(
        identified(body, "index_id", "reconciliation_index_", "index_digest")
    )
    atomic_write_text(root / "reconciliation" / "artifact-index.json", pretty_json(index))
    return index


def _canonical_id(value: dict[str, object]) -> str:
    schema = str(value.get("schema"))
    field = {
        "omiv.remote-artifact-locator.v1": "locator_id",
        "omiv.remote-snapshot-plan.v1": "plan_id",
        "omiv.remote-collection-execution-record.v1": "execution_id",
        "omiv.remote-member-record.v1": "member_id",
        "omiv.remote-snapshot-manifest.v1": "manifest_id",
        "omiv.shard-topology.v1": "topology_id",
        "omiv.shard-completeness-assessment.v1": "assessment_id",
        "omiv.remote-snapshot-expectation.v1": "expectation_id",
        "omiv.remote-publisher-authority-evaluation.v1": "authority_evaluation_id",
        "omiv.remote-local-reconciliation-policy.v1": "policy_id",
        "omiv.remote-local-reconciliation-comparison.v1": "comparison_id",
        "omiv.remote-local-reconciliation-evidence.v1": "evidence_id",
        "omiv.remote-local-reconciliation-report.v1": "report_id",
        "omiv.remote-local-integration.v1": "integration_id",
        "omiv.reconciliation-local-manifest-reference.v1": "reference_id",
        "omiv.reconciliation-practice-profile.v1": "profile_id",
        "omiv.xai-pinned-metadata-practice-evidence.v1": "evidence_id",
        "omiv.xai-public-artifact-metadata-case-study.v1": "report_id",
        "omiv.supplied-shard-index-fixture.v1": "fixture_id",
        "omiv.signed-object-envelope.v1": "envelope_id",
        "omiv.signature-report.v1": "report_id",
        "omiv.trust-policy.v1": "policy_id",
        "omiv.trust-bundle.v1": "bundle_id",
    }.get(schema)
    if field is None or not isinstance(value.get(field), str):
        raise ValueError(f"generated object lacks canonical identity: {schema}")
    return str(value[field])


if __name__ == "__main__":
    generate_all_reconciliation_examples(Path.cwd())
