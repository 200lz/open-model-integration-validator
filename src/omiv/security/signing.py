"""Phase 5D signed-envelope linkage for Phase 5F records."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.security.building import identified
from omiv.security.models import SignedSecurityEvidenceLinkage
from omiv.trust.models import SignedObjectEnvelope


def build_signed_security_linkage(
    envelope: SignedObjectEnvelope,
    *,
    trust_status: str,
) -> SignedSecurityEvidenceLinkage:
    allowed = {
        "SECURITY_SCAN_EXECUTION_RECORD",
        "SECURITY_EVIDENCE_BUNDLE",
        "SECURITY_EVALUATION",
    }
    if envelope.signed_object_type.value not in allowed:
        raise OmivInputError("signed envelope does not contain Phase 5F security evidence")
    purpose = envelope.signatures[0].purpose.value
    if any(item.purpose.value != purpose for item in envelope.signatures):
        raise OmivInputError("security envelope has mixed signature purposes")
    body = {
        "schema": "omiv.signed-security-evidence-linkage.v1",
        "object_id": envelope.signed_object_id,
        "object_digest": envelope.signed_object_digest,
        "envelope_id": envelope.envelope_id,
        "envelope_digest": envelope.envelope_digest,
        "signature_purpose": purpose,
        "trust_status": trust_status,
        "coverage_unchanged": True,
        "verdict_unchanged": True,
        "limitations": [
            "A signature proves a key signed the record; it does not prove scanner correctness.",
            "Signing does not upgrade findings, coverage, payload integrity, or runtime safety.",
        ],
    }
    return SignedSecurityEvidenceLinkage.model_validate(
        identified(body, "linkage_id", "signed_security_", "linkage_digest")
    )
