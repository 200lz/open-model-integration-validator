import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.passport.builder import build_passport
from omiv.passport.models import (
    CustodyStatus,
    CustodySummary,
    EvidenceAvailability,
    EvidenceReference,
    ModelPassport,
    OriginIdentity,
    PassportStageName,
    PassportStageStatus,
    ReferenceVerificationMode,
    RuntimeSummary,
    SecuritySummary,
    SummaryStatus,
    TrustOutcome,
    UsageOutcome,
    VerificationMode,
)
from omiv.passport.policy import (
    evaluate_usage_profiles,
    passport_policy,
    profile_policy_digest,
)
from omiv.passport.reporting import pretty_passport_json, render_passport_markdown
from omiv.passport.verification import load_passport, verify_passport
from omiv.validation.models import ValidationInventory
from omiv.validation.reporting import load_validation_inventory

ROOT = Path(__file__).parents[1]
IQ_VALIDATION = ROOT / "validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json"


@pytest.fixture(scope="module")
def validation() -> ValidationInventory:
    return load_validation_inventory(IQ_VALIDATION)


@pytest.fixture(scope="module")
def passport(validation: ValidationInventory) -> ModelPassport:
    return build_passport(
        validation,
        validation_reference="validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json",
    )


def _with_digest(data: dict[str, object]) -> dict[str, object]:
    body = dict(data)
    body.pop("passport_digest", None)
    data["passport_digest"] = canonical_sha256(body)
    return data


def test_generation_and_rendering_are_deterministic(
    validation: ValidationInventory, passport: ModelPassport
) -> None:
    second = build_passport(
        validation,
        validation_reference="validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json",
    )
    assert second == passport
    assert pretty_passport_json(second) == pretty_passport_json(passport)
    assert render_passport_markdown(second) == render_passport_markdown(passport)
    assert len(pretty_passport_json(passport)) < 50_000


def test_stable_identity_changes_with_evidence(validation: ValidationInventory) -> None:
    original = build_passport(validation)
    changed = validation.model_copy(update={"inventory_digest": "f" * 64})
    assert build_passport(changed).passport_id != original.passport_id


def test_stable_identity_changes_with_policy(
    validation: ValidationInventory, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = build_passport(validation)
    trusted = passport_policy()
    changed = trusted.model_copy(update={"policy_digest": "f" * 64})
    monkeypatch.setattr("omiv.passport.builder.passport_policy", lambda: changed)
    assert build_passport(validation).passport_id != original.passport_id


@pytest.mark.parametrize("field", ["generated_at", "timestamp", "hostname"])
def test_nondeterministic_fields_are_rejected(passport: ModelPassport, field: str) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    data[field] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValidationError, match="Extra inputs"):
        ModelPassport.model_validate(data)


def test_unknown_fields_and_malformed_status_are_rejected(passport: ModelPassport) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    data["subject"]["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        ModelPassport.model_validate(data)
    data = passport.model_dump(mode="json", by_alias=True)
    data["evidence_stages"][0]["status"] = "GREEN"
    with pytest.raises(ValidationError):
        ModelPassport.model_validate(data)


def test_absolute_paths_are_rejected(passport: ModelPassport) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    reference = next(
        item for item in data["evidence_references"] if item["role"] == "validation_inventory"
    )
    reference["relative_path"] = "/home/user/private.json"
    with pytest.raises(ValidationError, match="repository-relative"):
        ModelPassport.model_validate(data)


def test_subject_and_generic_local_origin() -> None:
    with pytest.raises(ValidationError):
        OriginIdentity(origin_type="huggingface", provider="huggingface")
    local = OriginIdentity(origin_type="local_file")
    assert local.repository is None
    assert local.resolved_revision is None


def test_stage_reconstruction_has_no_trust_escalation(passport: ModelPassport) -> None:
    stages = {item.stage: item.status for item in passport.evidence_stages}
    assert set(stages) == set(PassportStageName)
    assert stages[PassportStageName.ARTIFACT_IDENTITY] == PassportStageStatus.PASS
    assert stages[PassportStageName.FORMAT_STRUCTURE] == PassportStageStatus.PASS
    assert stages[PassportStageName.SEMANTIC_MAPPING] == PassportStageStatus.PASS
    assert stages[PassportStageName.CONVERTER_RULE_SUPPORT] == PassportStageStatus.AVAILABLE
    assert (
        stages[PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE]
        == PassportStageStatus.UNAVAILABLE
    )
    assert stages[PassportStageName.PAYLOAD_INTEGRITY] == PassportStageStatus.NOT_CHECKED
    assert stages[PassportStageName.SECURITY_INSPECTION] == PassportStageStatus.NOT_CHECKED
    assert stages[PassportStageName.CUSTODY_CHAIN] == PassportStageStatus.UNAVAILABLE
    assert stages[PassportStageName.RUNTIME_PARITY] == PassportStageStatus.NOT_CHECKED


def test_trust_summary_is_multidimensional(passport: ModelPassport) -> None:
    trust = passport.trust_summary
    assert trust.identity_status == TrustOutcome.IDENTITY_VERIFIED
    assert trust.structural_status == TrustOutcome.STRUCTURALLY_VALIDATED_WITH_LIMITATIONS
    assert trust.provenance_status == TrustOutcome.EVIDENCE_INCOMPLETE
    assert trust.payload_status == TrustOutcome.NOT_ASSESSED
    assert trust.security_status == TrustOutcome.NOT_ASSESSED
    assert trust.custody_status == TrustOutcome.TRUST_CHAIN_INCOMPLETE
    assert trust.runtime_status == TrustOutcome.NOT_ASSESSED
    assert "PASS" not in {value.value for _, value in trust}


def test_failed_and_incomplete_structural_evidence(passport: ModelPassport) -> None:
    statuses = {item.stage: item.status for item in passport.evidence_stages}
    statuses[PassportStageName.HEADER_INTEGRITY] = PassportStageStatus.FAIL
    profiles = evaluate_usage_profiles(statuses, passport_policy())
    assert any(item.outcome == UsageOutcome.NOT_SUITABLE for item in profiles)
    statuses[PassportStageName.HEADER_INTEGRITY] = PassportStageStatus.UNAVAILABLE
    assert evaluate_usage_profiles(statuses, passport_policy()) == evaluate_usage_profiles(
        statuses, passport_policy()
    )


def test_usage_profile_results(passport: ModelPassport) -> None:
    results = {item.profile: item for item in passport.usage_profiles}
    assert results["local_experimentation"].outcome == UsageOutcome.SUITABLE_WITH_LIMITATIONS
    assert results["team_structural_intake"].outcome == UsageOutcome.SUITABLE_WITH_LIMITATIONS
    assert results["enterprise_structural_review"].outcome == UsageOutcome.REVIEW_REQUIRED
    assert results["regulated_production"].outcome == UsageOutcome.NOT_SUITABLE
    assert PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE in results[
        "regulated_production"
    ].unmet_stages


def test_missing_identity_blocks_every_profile(passport: ModelPassport) -> None:
    statuses = {item.stage: item.status for item in passport.evidence_stages}
    statuses[PassportStageName.ARTIFACT_IDENTITY] = PassportStageStatus.FAIL
    results = evaluate_usage_profiles(statuses, passport_policy())
    blocked = {UsageOutcome.NOT_SUITABLE, UsageOutcome.REVIEW_REQUIRED}
    assert all(item.outcome in blocked for item in results)
    assert all(item.outcome != UsageOutcome.SUITABLE_WITH_LIMITATIONS for item in results)


def test_profile_policy_digest_is_stable() -> None:
    policy = passport_policy()
    assert policy == passport_policy()
    assert profile_policy_digest(policy) == profile_policy_digest(passport_policy())
    assert policy.policy_digest == passport_policy().policy_digest


def test_zero_event_custody_and_fake_verified_rejected(passport: ModelPassport) -> None:
    custody = passport.custody_summary
    assert custody.event_count == 0
    assert custody.status == CustodyStatus.NOT_AVAILABLE
    with pytest.raises(ValidationError, match="zero-event custody"):
        CustodySummary.model_validate(
            {**custody.model_dump(mode="json"), "status": CustodyStatus.VERIFIED}
        )


def test_custody_event_invariants(passport: ModelPassport) -> None:
    data = passport.custody_summary.model_dump(mode="json")
    data.update({"event_count": 1, "status": "INCOMPLETE"})
    with pytest.raises(ValidationError, match="chain identity"):
        CustodySummary.model_validate(data)
    data["broken_links"] = -1
    with pytest.raises(ValidationError):
        CustodySummary.model_validate(data)
    data.update(
        {
            "chain_id": "future-chain",
            "chain_schema": "omiv.model-chain-of-custody.future",
            "first_event_digest": "1" * 64,
            "latest_event_digest": "2" * 64,
            "broken_links": 0,
            "revoked_events": 1,
        }
    )
    assert CustodySummary.model_validate(data).revoked_events == 1


def test_evidence_graph_is_not_a_custody_ledger(passport: ModelPassport) -> None:
    data = passport.custody_summary.model_dump(mode="json")
    data["chain_schema"] = "omiv.validation-evidence-graph.v1"
    with pytest.raises(ValidationError, match="zero-event custody"):
        CustodySummary.model_validate(data)


def test_security_and_runtime_remain_unchecked(passport: ModelPassport) -> None:
    assert passport.security_summary.status == SummaryStatus.NOT_CHECKED
    assert passport.security_summary.scanner_results == []
    assert passport.runtime_summary.status == SummaryStatus.NOT_CHECKED
    assert passport.runtime_summary.compatibility_status == SummaryStatus.NOT_CHECKED
    with pytest.raises(ValidationError, match="scanner results"):
        SecuritySummary.model_validate(
            {**passport.security_summary.model_dump(mode="json"), "status": "PASS"}
        )
    with pytest.raises(ValidationError, match="observation digest"):
        RuntimeSummary(status="PASS", compatibility_status="PASS")


def test_future_evidence_reference_is_schema_valid() -> None:
    reference = EvidenceReference(
        role="future_security_evidence",
        schema="omiv.security-evidence.future",
        digest="a" * 64,
        availability=EvidenceAvailability.DIGEST_ONLY,
        verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
    )
    assert reference.role == "future_security_evidence"


def test_tamper_detection_and_summary_reconstruction(
    passport: ModelPassport, tmp_path: Path
) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    data["warnings"][0] = "Everything is safe."
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(OmivInputError, match="digest mismatch"):
        load_passport(path)
    data = passport.model_dump(mode="json", by_alias=True)
    data["trust_summary"]["runtime_status"] = "IDENTITY_VERIFIED"
    path.write_text(json.dumps(_with_digest(data)), encoding="utf-8")
    with pytest.raises(OmivInputError, match="trust-summary reconstruction"):
        load_passport(path)


@pytest.mark.parametrize(
    ("identity_field", "reference_role"),
    [
        ("evidence_graph_digest", "evidence_graph"),
        ("artifact_index_digest", "artifact_index"),
        ("model_pack_digest", "model_pack"),
        ("ontology_policy_digest", "ontology_policy"),
        ("mapping_policy_digest", "mapping_policy"),
    ],
)
def test_stale_linkage_rejected(
    passport: ModelPassport,
    tmp_path: Path,
    identity_field: str,
    reference_role: str,
) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    data["evidence_identity"][identity_field] = "f" * 64
    path = tmp_path / "stale.json"
    path.write_text(json.dumps(_with_digest(data)), encoding="utf-8")
    with pytest.raises(OmivInputError, match="mismatch"):
        load_passport(path)


def test_digest_only_and_full_offline_verification(
    passport: ModelPassport, tmp_path: Path
) -> None:
    path = tmp_path / "passport.json"
    path.write_text(pretty_passport_json(passport), encoding="utf-8")
    digest = verify_passport(path, digest_only=True)
    assert digest.mode == VerificationMode.DIGEST_ONLY_VERIFICATION
    full = verify_passport(path, root=ROOT)
    assert full.mode == VerificationMode.FULL_VERIFICATION


def test_missing_validation_reference_is_rejected(
    passport: ModelPassport, tmp_path: Path
) -> None:
    data = passport.model_dump(mode="json", by_alias=True)
    reference = next(
        item for item in data["evidence_references"] if item["role"] == "validation_inventory"
    )
    reference["relative_path"] = "validations/missing.json"
    path = tmp_path / "missing.json"
    path.write_text(json.dumps(_with_digest(data)), encoding="utf-8")
    with pytest.raises(OmivInputError, match="missing"):
        verify_passport(path, root=ROOT)


def test_markdown_summary_limitations_references_and_escaping(
    passport: ModelPassport,
) -> None:
    escaped = passport.model_copy(
        update={"subject": passport.subject.model_copy(update={"display_name": "A | B <C>"})}
    )
    markdown = render_passport_markdown(escaped)
    assert "A \\| B &lt;C&gt;" in markdown
    assert "Compact Summary" in markdown
    assert "Limitations" in markdown
    assert "Evidence References" in markdown
    assert "NOT_AVAILABLE" in markdown
    assert "safe to execute" in markdown
    assert "SAFE TO RUN" not in markdown
    assert "No Model Chain of Custody ledger has been recorded" in markdown
    assert "it is not a custody ledger" in markdown


def test_passport_contains_no_private_paths_or_false_claims(passport: ModelPassport) -> None:
    text = pretty_passport_json(passport) + render_passport_markdown(passport)
    for forbidden in (
        "/home/",
        "/tmp/",
        "github.com/200lz",
        "Authorization",
        "Bearer ",
        "X-Amz-",
        "NO SECURITY ISSUES FOUND",
        "SAFE TO RUN",
    ):
        assert forbidden not in text


def test_cli_create_verify_show_and_exit_codes(tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "passport.json"
    markdown = tmp_path / "passport.md"
    create = runner.invoke(
        app,
        [
            "passport",
            "create",
            "--validation",
            str(IQ_VALIDATION),
            "--output",
            str(output),
            "--markdown-output",
            str(markdown),
            "--root",
            str(ROOT),
        ],
    )
    assert create.exit_code == 0
    assert "PASS Model Passport" in create.stdout
    assert runner.invoke(
        app,
        ["passport", "verify", "--input", str(output), "--root", str(ROOT)],
    ).exit_code == 0
    show = runner.invoke(app, ["passport", "show", "--input", str(output)])
    assert show.exit_code == 0
    assert "Compact Summary" in show.stdout
    assert runner.invoke(
        app,
        [
            "passport",
            "verify",
            "--input",
            str(output),
            "--root",
            str(ROOT),
            "--profile",
            "regulated_production",
        ],
    ).exit_code == 1
    assert runner.invoke(
        app,
        [
            "passport",
            "verify",
            "--input",
            str(output),
            "--root",
            str(ROOT),
            "--profile",
            "unknown",
        ],
    ).exit_code == 2
