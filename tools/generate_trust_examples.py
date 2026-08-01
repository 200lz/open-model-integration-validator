"""Generate compact deterministic Phase 5D public-only examples and reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omiv.attestations.models import ArtifactAttestation
from omiv.attestations.segment import build_attestation_custody_segment
from omiv.canonical import canonical_sha256
from omiv.safe_write import atomic_write_text
from omiv.trust.models import (
    KeyUsage,
    RevocationReason,
    RevocationScope,
    SignaturePurpose,
    SignedObjectType,
    SignerIdentityKind,
    ValidityWindow,
)
from omiv.trust.reporting import render_markdown
from omiv.trust.signing import (
    build_binding,
    build_delegation,
    build_descriptor,
    build_evaluation_context,
    build_key_identity,
    build_policy,
    build_revocation,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.verification import pretty_json, verify_envelope

# TEST-ONLY published RFC 8032 vectors. They are public and have no security value.
RFC8032_VECTOR_1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_VECTOR_2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"


def _key(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("example source must be a JSON object")
    return value


def _synthetic_passport(path: Path) -> dict[str, Any]:
    """Derive a fictional non-publisher Passport fixture and reconstruct its identity."""
    raw_text = path.read_text(encoding="utf-8")
    for old, new in {
        "Kimi K3": "Synthetic Transformer",
        "kimi-k3": "synthetic-transformer",
        "Kimi-K3": "Synthetic-Transformer",
        "unsloth": "synthetic-project",
        "Unsloth": "Synthetic Project",
        "huggingface": "internal_registry",
        "UD-Q4_K_XL": "SYNTHETIC-F16",
    }.items():
        raw_text = raw_text.replace(old, new)
    value = json.loads(raw_text)
    if not isinstance(value, dict):
        raise ValueError("synthetic Passport source must be a JSON object")
    if any(term in json.dumps(value).lower() for term in ("kimi", "unsloth", "moonshot")):
        raise ValueError("synthetic Passport retained a publisher identity")
    if value["schema"] == "omiv.model-passport.v1":
        identity = {
            "schema": value["schema"],
            "subject": value["subject"],
            "artifact_identity": value["artifact_identity"],
            "source_evidence_bundle_digest": value["evidence_identity"][
                "validation_inventory_digest"
            ],
            "passport_policy_digest": value["policy_identity"]["passport_policy_digest"],
        }
    else:
        identity = {
            "schema": value["schema"],
            "base_passport_id": value["base_passport_id"],
            "base_passport_digest": value["base_passport_digest"],
            "subject": value["subject"],
            "artifact_identity": value["artifact_identity"],
            "custody_ledger_digest": value["custody_summary"]["ledger_digest"],
            "passport_policy_digest": value["policy_identity"]["passport_policy_digest"],
        }
    value["passport_id"] = "mp_" + canonical_sha256(identity)[:32]
    value.pop("passport_digest")
    value["passport_digest"] = canonical_sha256(value)
    return value


def _write(root: Path, relative: str, value: object) -> None:
    path = root / relative
    text = value if isinstance(value, str) else pretty_json(value)
    atomic_write_text(path, text)


def generate(repository: Path, output_root: Path) -> list[Path]:
    source = repository / "attestations/examples"
    transformation = _load(source / "synthetic_transformation.attestation.json")
    acquisition = _load(source / "synthetic_local_acquisition.attestation.json")
    evidence_acquisition = _load(source / "synthetic_evidence_linked_acquisition.attestation.json")
    quantization = _load(source / "synthetic_quantization.attestation.json")
    execution = transformation["execution_record"]
    if not isinstance(execution, dict):
        raise ValueError("synthetic transformation lacks an execution record")
    quantization_execution = quantization["execution_record"]
    if not isinstance(quantization_execution, dict):
        raise ValueError("synthetic quantization lacks an execution record")
    passport_v1 = _synthetic_passport(
        repository / "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport.json"
    )
    passport_v2 = _synthetic_passport(
        repository / "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport-with-custody.json"
    )
    ledger = _load(repository / "custody/examples/synthetic_transformation.custody-ledger.json")
    event = ledger["events"][0]
    if not isinstance(event, dict):
        raise ValueError("synthetic custody ledger lacks an event")
    segment = build_attestation_custody_segment(
        ArtifactAttestation.model_validate(transformation),
        attestation_reference=("attestations/examples/synthetic_transformation.attestation.json"),
    ).model_dump(mode="json", by_alias=True)

    private = _key(RFC8032_VECTOR_1)
    types = [
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignedObjectType.TOOL_EXECUTION_RECORD,
        SignedObjectType.CUSTODY_EVENT,
        SignedObjectType.CUSTODY_SEGMENT,
        SignedObjectType.MODEL_PASSPORT,
    ]
    purposes = [
        SignaturePurpose.ATTESTATION_ISSUANCE,
        SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
        SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
        SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
        SignaturePurpose.PASSPORT_ISSUANCE,
    ]
    project_key = build_key_identity(
        private,
        allowed_object_types=types,
        allowed_purposes=purposes,
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING, KeyUsage.SIGN_OMIV_OBJECT],
        namespaces=["synthetic"],
    )
    signer = build_signer_identity(
        SignerIdentityKind.PROJECT_MAINTAINER_DECLARED,
        "Synthetic Project Maintainer",
        role="maintainer",
        namespace="synthetic",
    )
    binding = build_binding(signer, project_key)
    root = build_trust_root(project_key, delegation_allowed=True, maximum_delegation_depth=1)
    policy = build_policy(
        "project_maintainer_release",
        object_types=types,
        purposes=purposes,
        namespaces=["synthetic"],
    )
    bundle = build_trust_bundle([root], [project_key], identities=[signer], bindings=[binding])
    context = build_evaluation_context(policy, evaluation_time="2026-07-31T00:00:00Z")

    artifacts: dict[str, object] = {
        "trust/examples/project-maintainer.key-identity.json": project_key,
        "trust/examples/project-maintainer.signer-identity.json": signer,
        "trust/examples/project-maintainer.binding.json": binding,
        "trust/examples/project.trust-root.json": root,
        "trust/examples/project-trust-policy.json": policy,
        "trust/examples/project-trust-bundle.json": bundle,
        "trust/examples/evaluation-context.json": context,
    }

    def signed_case(
        name: str,
        value: dict[str, Any],
        object_type: SignedObjectType,
        purpose: SignaturePurpose,
        *,
        use_bundle: object = bundle,
        use_key: object = project_key,
        use_private: Ed25519PrivateKey = private,
        use_binding_id: str | None = binding.binding_id,
        use_policy: object = policy,
        use_context: object = context,
    ) -> None:
        selected_policy = use_policy
        selected_key = use_key
        descriptor = build_descriptor(
            value,
            object_type,
            purpose,
            policy_id=selected_policy.policy_id,
            namespace="synthetic",
        )
        signature = build_signature_record(
            descriptor,
            use_private,
            selected_key,
            binding_id=use_binding_id,
        )
        envelope = build_signed_envelope(value, object_type, [signature], keys=[selected_key])
        report = verify_envelope(envelope, use_bundle, selected_policy, use_context)
        artifacts[f"trust/examples/{name}.signed-envelope.json"] = envelope
        artifacts[f"reports/trust/{name}.signature-report.json"] = report
        artifacts[f"reports/trust/{name}.signature-report.md"] = render_markdown(report)

    signed_case(
        "trusted-transformation",
        transformation,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
    )
    signed_case(
        "signed-declared-acquisition",
        acquisition,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
    )
    signed_case(
        "signed-evidence-linked-acquisition",
        evidence_acquisition,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
    )
    signed_case(
        "signed-quantization",
        quantization,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
    )
    signed_case(
        "signed-execution-record",
        execution,
        SignedObjectType.TOOL_EXECUTION_RECORD,
        SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
    )
    signed_case(
        "signed-quantization-execution-record",
        quantization_execution,
        SignedObjectType.TOOL_EXECUTION_RECORD,
        SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
    )
    signed_case(
        "signed-custody-event",
        event,
        SignedObjectType.CUSTODY_EVENT,
        SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
    )
    signed_case(
        "signed-custody-segment",
        segment,
        SignedObjectType.CUSTODY_SEGMENT,
        SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
    )
    signed_case(
        "signed-passport-v1",
        passport_v1,
        SignedObjectType.MODEL_PASSPORT,
        SignaturePurpose.PASSPORT_ISSUANCE,
    )
    signed_case(
        "signed-passport-v2",
        passport_v2,
        SignedObjectType.MODEL_PASSPORT,
        SignaturePurpose.PASSPORT_ISSUANCE,
    )

    unknown_private = _key(RFC8032_VECTOR_2)
    unknown_key = build_key_identity(
        unknown_private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        namespaces=["synthetic"],
    )
    signed_case(
        "unknown-key",
        transformation,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        use_key=unknown_key,
        use_private=unknown_private,
        use_binding_id=None,
    )

    revocation = build_revocation(
        RevocationScope.KEY, project_key.key_id, RevocationReason.KEY_COMPROMISE
    )
    revoked_bundle = build_trust_bundle(
        [root],
        [project_key],
        identities=[signer],
        bindings=[binding],
        revocations=[revocation],
    )
    artifacts["trust/examples/project-key.revocation-record.json"] = revocation
    artifacts["trust/examples/revoked-project-trust-bundle.json"] = revoked_bundle
    signed_case(
        "revoked-attestation",
        transformation,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        use_bundle=revoked_bundle,
    )

    validity = ValidityWindow(
        not_before="2025-01-01T00:00:00Z",
        not_after="2025-12-31T23:59:59Z",
    )
    expired_key = build_key_identity(
        private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        namespaces=["synthetic"],
        validity=validity,
    )
    expired_binding = build_binding(signer, expired_key, validity=validity)
    expired_root = build_trust_root(expired_key, validity=validity)
    expiration_policy = build_policy(
        "enterprise_offline_release",
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        namespaces=["synthetic"],
        require_expiration=True,
    )
    expired_bundle = build_trust_bundle(
        [expired_root],
        [expired_key],
        identities=[signer],
        bindings=[expired_binding],
    )
    expiration_context = build_evaluation_context(
        expiration_policy, evaluation_time="2026-07-31T00:00:00Z"
    )
    artifacts["trust/examples/expiration-trust-policy.json"] = expiration_policy
    artifacts["trust/examples/expired-project-trust-bundle.json"] = expired_bundle
    artifacts["trust/examples/expired-evaluation-context.json"] = expiration_context
    signed_case(
        "expired-attestation",
        transformation,
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        use_bundle=expired_bundle,
        use_key=expired_key,
        use_binding_id=expired_binding.binding_id,
        use_policy=expiration_policy,
        use_context=expiration_context,
    )

    delegate_key = build_key_identity(
        unknown_private,
        allowed_object_types=[SignedObjectType.CUSTODY_SEGMENT],
        allowed_purposes=[SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE],
        namespaces=["synthetic"],
    )
    delegate_signer = build_signer_identity(
        SignerIdentityKind.TEAM_DECLARED,
        "Synthetic Release Team",
        role="release",
        namespace="synthetic",
    )
    delegate_binding = build_binding(delegate_signer, delegate_key)
    delegation = build_delegation(
        private,
        project_key,
        delegate_key,
        purposes=[SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE],
        object_types=[SignedObjectType.CUSTODY_SEGMENT],
        namespaces=["synthetic"],
    )
    delegation_policy = build_policy(
        "team_release",
        object_types=[SignedObjectType.CUSTODY_SEGMENT],
        purposes=[SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE],
        namespaces=["synthetic"],
        allow_delegation=True,
        maximum_delegation_depth=1,
    )
    delegated_bundle = build_trust_bundle(
        [root],
        [project_key, delegate_key],
        identities=[delegate_signer, signer],
        bindings=[delegate_binding, binding],
        delegations=[delegation],
    )
    delegation_context = build_evaluation_context(
        delegation_policy, evaluation_time="2026-07-31T00:00:00Z"
    )
    artifacts.update(
        {
            "trust/examples/delegate.key-identity.json": delegate_key,
            "trust/examples/delegate.signer-identity.json": delegate_signer,
            "trust/examples/delegate.binding.json": delegate_binding,
            "trust/examples/delegation-record.json": delegation,
            "trust/examples/team-trust-policy.json": delegation_policy,
            "trust/examples/delegated-trust-bundle.json": delegated_bundle,
            "trust/examples/delegation-evaluation-context.json": delegation_context,
        }
    )
    signed_case(
        "delegated-custody-segment",
        segment,
        SignedObjectType.CUSTODY_SEGMENT,
        SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
        use_bundle=delegated_bundle,
        use_key=delegate_key,
        use_private=unknown_private,
        use_binding_id=delegate_binding.binding_id,
        use_policy=delegation_policy,
        use_context=delegation_context,
    )

    for relative, value in sorted(artifacts.items()):
        _write(output_root, relative, value)
    return [output_root / name for name in sorted(artifacts)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output-root", type=Path, default=Path("."))
    args = parser.parse_args()
    paths = generate(args.repository.resolve(), args.output_root.resolve())
    print(f"generated {len(paths)} deterministic public-only Phase 5D artifacts")


if __name__ == "__main__":
    main()
