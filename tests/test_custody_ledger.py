import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.custody.append import append_event
from omiv.custody.builder import (
    build_event,
    build_evidence_custody_ledger,
    ledger_digest,
)
from omiv.custody.models import (
    ActorReference,
    ArtifactReference,
    AssertionOrigin,
    CustodyEvent,
    CustodyEventInput,
    CustodyEventType,
    CustodyLedger,
    CustodyPolicyReference,
    EnvironmentReference,
    EventAuthenticity,
    EvidenceLinkageStatus,
    LifecycleCompleteness,
    OverallCustodyStatus,
    ReferenceStatus,
    SubjectContinuityStatus,
)
from omiv.custody.passport import (
    build_custody_linked_passport,
    load_custody_linked_passport,
    pretty_linked_passport_json,
    render_linked_passport_markdown,
    verify_custody_linked_passport,
)
from omiv.custody.policy import custody_policy, evaluate_completeness
from omiv.custody.reporting import (
    build_custody_report,
    load_custody_report,
    pretty_json,
    render_custody_markdown,
    verify_custody_report,
)
from omiv.custody.verification import (
    load_custody_ledger,
    reconstruct_subject_continuity,
    verify_custody_ledger,
)
from omiv.errors import OmivInputError
from omiv.passport.models import ModelPassport
from omiv.passport.verification import load_passport, verify_passport
from omiv.validation.models import ValidationInventory
from omiv.validation.reporting import load_validation_inventory

ROOT = Path(__file__).parents[1]
IQ_PASSPORT = ROOT / "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json"
IQ_VALIDATION = ROOT / "validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json"
IQ_LEDGER = ROOT / "custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json"
IQ_REPORT = ROOT / "reports/custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody.report.json"
IQ_LINKED = ROOT / "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport-with-custody.json"


@pytest.fixture(scope="module")
def passport() -> ModelPassport:
    return load_passport(IQ_PASSPORT)


@pytest.fixture(scope="module")
def validation() -> ValidationInventory:
    return load_validation_inventory(IQ_VALIDATION)


@pytest.fixture(scope="module")
def ledger(passport: ModelPassport, validation: ValidationInventory) -> CustodyLedger:
    return build_evidence_custody_ledger(
        passport,
        validation,
        passport_reference="passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json",
        validation_reference=(
            "validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json"
        ),
        selected_profile="evidence_segment",
    )


def _input(event: CustodyEvent, **updates: object) -> CustodyEventInput:
    raw = event.model_dump(mode="json", by_alias=True)
    for field in (
        "event_id",
        "sequence",
        "chain_id",
        "previous_event_digest",
        "event_digest",
        "authenticity",
        "attestation_status",
    ):
        raw.pop(field)
    raw["schema"] = "omiv.custody-event-input.v1"
    raw.update(updates)
    return CustodyEventInput.model_validate(raw)


def _artifact(reference: ArtifactReference, **updates: object) -> ArtifactReference:
    raw = reference.model_dump(mode="json")
    raw.pop("identity_digest")
    raw.update(updates)
    identity = dict(raw)
    identity.pop("passport_id")
    identity.pop("passport_digest")
    identity.pop("validation_inventory_digest")
    raw["identity_digest"] = canonical_sha256(identity)
    return ArtifactReference.model_validate(raw)


def _user_input(
    subject: ArtifactReference,
    event_type: CustodyEventType = CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
) -> CustodyEventInput:
    return CustodyEventInput(
        event_type=event_type,
        subject=subject,
        input_artifacts=[],
        output_artifacts=[],
        action="Record a user-declared lifecycle claim.",
        assertion_origin=AssertionOrigin.USER_DECLARED,
        actor_reference=ActorReference(status=ReferenceStatus.UNAVAILABLE),
        environment_reference=EnvironmentReference(status=ReferenceStatus.UNAVAILABLE),
        policy_references=[
            CustodyPolicyReference(
                policy_id="custody_policy",
                policy_digest=custody_policy().policy_digest,
            )
        ],
        evidence_references=[],
        event_claims={"declaration": "no external attestation"},
        limitations=["This event is user-declared and unattested."],
    )


def test_event_and_ledger_identity_are_deterministic(ledger: CustodyLedger) -> None:
    assert ledger == CustodyLedger.model_validate(ledger.model_dump(mode="json", by_alias=True))
    first = ledger.events[0]
    rebuilt = build_event(
        _input(first),
        chain_id=ledger.chain_id,
        sequence=0,
        previous_event_digest=None,
    )
    assert rebuilt == first
    assert ledger_digest(ledger) == ledger.ledger_digest


@pytest.mark.parametrize("change", ["claim", "evidence", "policy", "parent"])
def test_event_identity_changes_with_canonical_inputs(
    ledger: CustodyLedger, change: str
) -> None:
    event = ledger.events[1]
    raw = _input(event).model_dump(mode="json", by_alias=True)
    previous = event.previous_event_digest
    if change == "claim":
        raw["event_claims"]["changed"] = True
    elif change == "evidence":
        raw["evidence_references"][0]["digest"] = "f" * 64
    elif change == "policy":
        raw["policy_references"][0]["policy_digest"] = "f" * 64
    else:
        previous = "f" * 64
    rebuilt = build_event(
        CustodyEventInput.model_validate(raw),
        chain_id=ledger.chain_id,
        sequence=event.sequence,
        previous_event_digest=previous,
    )
    assert rebuilt.event_id != event.event_id
    assert rebuilt.event_digest != event.event_digest


def test_event_has_no_timestamp_dependency(ledger: CustodyLedger) -> None:
    raw = _input(ledger.events[0]).model_dump(mode="json", by_alias=True)
    raw["timestamp"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValidationError, match="Extra inputs"):
        CustodyEventInput.model_validate(raw)


@pytest.mark.parametrize(
    "value",
    [
        "/tmp/private",
        "550e8400-e29b-41d4-a716-446655440000",
        "2026-01-01T00:00:00Z",
        "Bearer secret",
        "https://example.test/model?Signature=secret",
    ],
)
def test_event_rejects_absolute_paths_and_uuids(
    ledger: CustodyLedger, value: str
) -> None:
    event_input = _input(ledger.events[0], event_claims={"unsafe": value})
    with pytest.raises(ValidationError, match="paths, timestamps, UUIDs, or secrets"):
        build_event(
            event_input,
            chain_id=ledger.chain_id,
            sequence=0,
            previous_event_digest=None,
        )


def test_unknown_fields_and_event_types_rejected(ledger: CustodyLedger) -> None:
    raw = _input(ledger.events[0]).model_dump(mode="json", by_alias=True)
    raw["unknown"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        CustodyEventInput.model_validate(raw)
    raw.pop("unknown")
    raw["event_type"] = "MAGIC_EVENT"
    with pytest.raises(ValidationError):
        CustodyEventInput.model_validate(raw)


def test_valid_genesis_and_linear_chain(ledger: CustodyLedger) -> None:
    assert ledger.events[0].previous_event_digest is None
    assert [item.sequence for item in ledger.events] == list(range(ledger.event_count))
    assert all(
        current.previous_event_digest == previous.event_digest
        for previous, current in zip(ledger.events, ledger.events[1:], strict=False)
    )


@pytest.mark.parametrize("mutation", ["missing", "reordered", "duplicate", "gap"])
def test_invalid_event_ordering_is_rejected(
    ledger: CustodyLedger, mutation: str
) -> None:
    raw = ledger.model_dump(mode="json", by_alias=True)
    if mutation == "missing":
        del raw["events"][0]
        raw["event_count"] -= 1
    elif mutation == "reordered":
        raw["events"][1], raw["events"][2] = raw["events"][2], raw["events"][1]
    elif mutation == "duplicate":
        raw["events"][1] = raw["events"][0]
    else:
        raw["events"][1]["sequence"] = 9
    with pytest.raises(ValidationError):
        CustodyLedger.model_validate(raw)


def test_two_genesis_and_unknown_parent_rejected(ledger: CustodyLedger) -> None:
    second = build_event(
        _input(ledger.events[1]),
        chain_id=ledger.chain_id,
        sequence=1,
        previous_event_digest=None,
    )
    raw = ledger.model_dump(mode="json", by_alias=True)
    raw["events"][1] = second.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="exactly one genesis"):
        CustodyLedger.model_validate(raw)
    second = build_event(
        _input(ledger.events[1]),
        chain_id=ledger.chain_id,
        sequence=1,
        previous_event_digest="f" * 64,
    )
    raw["events"][1] = second.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="parent link"):
        CustodyLedger.model_validate(raw)


def test_changed_event_and_ledger_tampering_detected(
    ledger: CustodyLedger, tmp_path: Path
) -> None:
    raw = ledger.model_dump(mode="json", by_alias=True)
    raw["events"][2]["action"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OmivInputError, match="event (ID|digest) mismatch"):
        load_custody_ledger(path)
    raw = ledger.model_dump(mode="json", by_alias=True)
    raw["overall_custody_status"] = "INTACT"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OmivInputError, match="ledger digest mismatch"):
        load_custody_ledger(path)


def test_subject_continuity_and_divergence(ledger: CustodyLedger) -> None:
    assert reconstruct_subject_continuity(ledger) == SubjectContinuityStatus.CONSISTENT
    changed = _artifact(ledger.subject, variant="different")
    event = build_event(
        _input(ledger.events[-1], subject=changed.model_dump(mode="json")),
        chain_id=ledger.chain_id,
        sequence=ledger.events[-1].sequence,
        previous_event_digest=ledger.events[-1].previous_event_digest,
    )
    divergent = ledger.model_copy(update={"events": [*ledger.events[:-1], event]})
    assert reconstruct_subject_continuity(divergent) == SubjectContinuityStatus.DIVERGED


@pytest.mark.parametrize(
    "field",
    [
        "resolved_revision",
        "artifact_set_digest",
        "variant",
    ],
)
def test_subject_identity_mismatches_diverge(
    ledger: CustodyLedger, field: str
) -> None:
    value = (
        "f" * 40
        if field == "resolved_revision"
        else "f" * 64
        if field.endswith("digest")
        else "x"
    )
    changed = _artifact(ledger.subject, **{field: value})
    event = build_event(
        _input(ledger.events[-1], subject=changed.model_dump(mode="json")),
        chain_id=ledger.chain_id,
        sequence=ledger.events[-1].sequence,
        previous_event_digest=ledger.events[-1].previous_event_digest,
    )
    candidate = ledger.model_copy(update={"events": [*ledger.events[:-1], event]})
    assert reconstruct_subject_continuity(candidate) == SubjectContinuityStatus.DIVERGED


def test_synthetic_transformation_relation(ledger: CustodyLedger) -> None:
    output = _artifact(ledger.subject, variant="synthetic-output", artifact_set_digest="e" * 64)
    event_input = _user_input(ledger.subject, CustodyEventType.TRANSFORMATION_RECORDED)
    event_input = event_input.model_copy(
        update={
            "input_artifacts": [ledger.subject],
            "output_artifacts": [output],
            "event_claims": {"relation": "synthetic-test-only"},
        }
    )
    updated = append_event(ledger, event_input)
    assert reconstruct_subject_continuity(updated) == SubjectContinuityStatus.CONSISTENT
    invalid = event_input.model_copy(update={"input_artifacts": [output]})
    with pytest.raises(OmivInputError, match="wrong input"):
        append_event(ledger, invalid)


def test_evidence_linkages_and_real_verification(ledger: CustodyLedger) -> None:
    assert verify_custody_ledger(IQ_LEDGER, ROOT) == ledger
    assert ledger.evidence_linkage == EvidenceLinkageStatus.VERIFIED
    assert all(
        reference.verification_mode == "full_verification"
        for event in ledger.events
        for reference in event.evidence_references
    )


def test_authenticity_is_not_implied_by_hash_integrity(ledger: CustodyLedger) -> None:
    assert ledger.ledger_integrity.value == "INTACT"
    assert ledger.event_authenticity_summary.statuses == [EventAuthenticity.EVIDENCE_DERIVED]
    assert ledger.event_authenticity_summary.unattested_event_count == ledger.event_count
    assert ledger.event_authenticity_summary.signed_event_count == 0
    assert all(
        event.actor_reference.status == ReferenceStatus.UNAVAILABLE
        for event in ledger.events
    )


def test_signed_origin_is_reserved(ledger: CustodyLedger) -> None:
    raw = _input(ledger.events[0]).model_dump(mode="json", by_alias=True)
    raw["assertion_origin"] = "SIGNED_ATTESTATION_RESERVED"
    with pytest.raises(ValidationError, match="reserved"):
        CustodyEventInput.model_validate(raw)


def test_system_observed_and_user_declared_authenticity(ledger: CustodyLedger) -> None:
    observed = _input(
        ledger.events[0], assertion_origin=AssertionOrigin.SYSTEM_OBSERVED.value
    )
    built = build_event(
        observed,
        chain_id=ledger.chain_id,
        sequence=0,
        previous_event_digest=None,
    )
    assert built.authenticity == EventAuthenticity.SYSTEM_OBSERVED
    appended = append_event(ledger, _user_input(ledger.subject))
    assert appended.events[-1].authenticity == EventAuthenticity.USER_DECLARED
    assert appended.events[-1].attestation_status.value == "UNATTESTED"


def test_completeness_profiles_and_missing_events(ledger: CustodyLedger) -> None:
    results = {
        item.profile: item for item in ledger.missing_event_analysis.profile_results
    }
    assert results["evidence_segment"].status == LifecycleCompleteness.COMPLETE
    for name in (
        "local_model_intake",
        "team_release",
        "enterprise_deployment",
        "regulated_runtime",
    ):
        assert results[name].status == LifecycleCompleteness.INCOMPLETE
    assert ledger.lifecycle_completeness == LifecycleCompleteness.INCOMPLETE
    assert ledger.overall_custody_status == OverallCustodyStatus.INCOMPLETE
    assert [item.value for item in ledger.missing_event_analysis.missing_event_types] == sorted(
        item.value for item in ledger.missing_event_analysis.missing_event_types
    )


def test_policy_digest_stability_and_unknown_profile() -> None:
    assert custody_policy() == custody_policy()
    with pytest.raises(OmivInputError, match="unknown custody profile"):
        evaluate_completeness([], "unknown")


def test_not_applicable_requires_policy_evidence(ledger: CustodyLedger) -> None:
    event = CustodyEventType.ARTIFACT_ACQUISITION_RECORDED
    with pytest.raises(OmivInputError, match="explicit policy evidence"):
        evaluate_completeness(
            [item.event_type for item in ledger.events],
            "evidence_segment",
            not_applicable_event_types={event: "f" * 64},
        )
    analysis = evaluate_completeness(
        [item.event_type for item in ledger.events],
        "evidence_segment",
        not_applicable_event_types={event: "f" * 64},
        not_applicable_policy_digests={"f" * 64},
    )
    assert event not in analysis.missing_event_types


def test_append_determinism_duplicate_and_divergence(ledger: CustodyLedger) -> None:
    event_input = _user_input(ledger.subject)
    first = append_event(ledger, event_input)
    second = append_event(ledger, event_input)
    assert first == second
    assert first.events[-1].sequence == ledger.event_count
    assert first.events[-1].previous_event_digest == ledger.latest_event_digest
    assert first.evidence_linkage == EvidenceLinkageStatus.PARTIAL
    with pytest.raises(OmivInputError, match="duplicate"):
        append_event(first, event_input)
    changed = _artifact(ledger.subject, variant="wrong")
    with pytest.raises(OmivInputError, match="divergence"):
        append_event(ledger, _user_input(changed))


def test_append_rejects_non_user_and_reserved(ledger: CustodyLedger) -> None:
    derived = _user_input(ledger.subject).model_copy(
        update={"assertion_origin": AssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE}
    )
    with pytest.raises(OmivInputError, match="USER_DECLARED"):
        append_event(ledger, derived)
    reserved = _user_input(
        ledger.subject, CustodyEventType.REVOCATION_RECORDED_RESERVED
    )
    with pytest.raises(OmivInputError, match="disallows"):
        append_event(ledger, reserved)


def test_report_and_markdown_are_deterministic(ledger: CustodyLedger) -> None:
    first = build_custody_report(ledger)
    second = build_custody_report(ledger)
    assert first == second
    assert pretty_json(first) == pretty_json(second)
    markdown = render_custody_markdown(first)
    assert markdown == render_custody_markdown(second)
    assert "Ledger integrity and lifecycle completeness are separate" in markdown
    assert "Missing Lifecycle Events" in markdown
    assert "does not authenticate an actor" in markdown
    assert len(pretty_json(ledger)) < 100_000


def test_report_and_ledger_verification() -> None:
    assert load_custody_report(IQ_REPORT) == verify_custody_report(
        IQ_REPORT, IQ_LEDGER, ROOT
    )


def test_linked_passport_and_v1_backward_compatibility(
    passport: ModelPassport, ledger: CustodyLedger
) -> None:
    original_bytes = IQ_PASSPORT.read_bytes()
    assert verify_passport(IQ_PASSPORT, root=ROOT).mode.value == "full_verification"
    assert IQ_PASSPORT.read_bytes() == original_bytes
    linked = build_custody_linked_passport(
        passport,
        ledger,
        ledger_reference="custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json",
    )
    assert linked.schema_id == "omiv.model-passport.v2"
    assert linked.passport_id != passport.passport_id
    assert linked.custody_summary.ledger_integrity.value == "INTACT"
    assert linked.custody_summary.lifecycle_completeness == LifecycleCompleteness.INCOMPLETE
    assert "CUSTODY VERIFIED" not in render_linked_passport_markdown(linked)
    assert pretty_linked_passport_json(linked) == pretty_linked_passport_json(linked)


def test_real_linked_passport_verification() -> None:
    linked = load_custody_linked_passport(IQ_LINKED)
    assert verify_custody_linked_passport(IQ_LINKED, root=ROOT) == linked
    assert verify_custody_linked_passport(IQ_LINKED, digest_only=True) == linked


def test_cli_exit_codes_and_show(tmp_path: Path) -> None:
    runner = CliRunner()
    assert runner.invoke(
        app, ["custody", "verify", "--input", str(IQ_LEDGER), "--root", str(ROOT)]
    ).exit_code == 0
    show = runner.invoke(app, ["custody", "show", "--input", str(IQ_LEDGER)])
    assert show.exit_code == 0
    assert "Event Timeline" in show.stdout
    enterprise = runner.invoke(
        app,
        [
            "custody",
            "create",
            "--passport",
            str(IQ_PASSPORT),
            "--validation",
            str(IQ_VALIDATION),
            "--profile",
            "enterprise_deployment",
            "--output",
            str(tmp_path / "ledger.json"),
            "--report-output",
            str(tmp_path / "report.json"),
            "--markdown-output",
            str(tmp_path / "report.md"),
            "--root",
            str(ROOT),
        ],
    )
    assert enterprise.exit_code == 1
    broken = tmp_path / "broken.json"
    raw = json.loads(IQ_LEDGER.read_text(encoding="utf-8"))
    raw["ledger_digest"] = "f" * 64
    broken.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(
        app, ["custody", "verify", "--input", str(broken), "--root", str(ROOT)]
    ).exit_code == 2


def test_cli_append_atomic_and_in_place_protection(
    ledger: CustodyLedger, tmp_path: Path
) -> None:
    runner = CliRunner()
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(_user_input(ledger.subject).model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )
    output = tmp_path / "appended.json"
    result = runner.invoke(
        app,
        [
            "custody",
            "append",
            "--ledger",
            str(IQ_LEDGER),
            "--event",
            str(event_path),
            "--output",
            str(output),
            "--root",
            str(ROOT),
        ],
    )
    assert result.exit_code == 0
    assert output.is_file()
    assert verify_custody_ledger(output, ROOT).event_count == ledger.event_count + 1
    assert IQ_LEDGER.read_bytes() == (ROOT / IQ_LEDGER.relative_to(ROOT)).read_bytes()
    in_place = runner.invoke(
        app,
        [
            "custody",
            "append",
            "--ledger",
            str(IQ_LEDGER),
            "--event",
            str(event_path),
            "--output",
            str(IQ_LEDGER),
        ],
    )
    assert in_place.exit_code == 2


def test_no_private_paths_or_false_claims(ledger: CustodyLedger) -> None:
    text = pretty_json(ledger) + render_custody_markdown(build_custody_report(ledger))
    for forbidden in (
        "/home/",
        "/tmp/",
        "Authorization",
        "Bearer ",
        "github.com/200lz",
        "actor verified",
        "event signed",
        "non-repudiation established",
        "custody legally proven",
    ):
        assert forbidden not in text
