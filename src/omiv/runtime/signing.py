"""Claim-preserving linkage for signed Phase 5G canonical evidence."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.runtime.building import identified
from omiv.runtime.models import SignedRuntimeLinkage
from omiv.trust.models import SignedObjectEnvelope, SignedObjectType

RUNTIME_SIGNED_TYPES = {
    SignedObjectType.DEPLOYMENT_INTENT,
    SignedObjectType.DEPLOYMENT_MANIFEST,
    SignedObjectType.DEPLOYMENT_RECORD,
    SignedObjectType.RUNTIME_OBSERVATION,
    SignedObjectType.CONTINUITY_EVALUATION,
}


def build_signed_runtime_linkage(
    envelope: SignedObjectEnvelope,
    *,
    trust_status: str,
) -> SignedRuntimeLinkage:
    if envelope.signed_object_type not in RUNTIME_SIGNED_TYPES:
        raise OmivInputError("signed envelope does not contain Phase 5G runtime evidence")
    body = {
        "schema": "omiv.signed-runtime-linkage.v1",
        "object_type": envelope.signed_object_type.value,
        "object_id": envelope.signed_object_id,
        "object_digest": envelope.signed_object_digest,
        "envelope_id": envelope.envelope_id,
        "envelope_digest": envelope.envelope_digest,
        "signature_purposes": sorted({x.purpose.value for x in envelope.signatures}),
        "evidence_origin_preserved": True,
        "authority_preserved": True,
        "coverage_preserved": True,
        "verdict_preserved": True,
        "limitations": [
            f"Signature trust status is {trust_status}; signing does not upgrade origin, "
            "authority, coverage, freshness, continuity, behavior, or safety."
        ],
    }
    return SignedRuntimeLinkage.model_validate(
        identified(body, "linkage_id", "signed_runtime_", "linkage_digest")
    )
