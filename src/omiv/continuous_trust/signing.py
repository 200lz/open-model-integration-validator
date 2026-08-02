"""External signed-object linkages that preserve Phase 5H claim strength."""

from omiv.continuous_trust.building import identified
from omiv.continuous_trust.models import SignedHistoricalLinkage
from omiv.trust.models import SignedObjectEnvelope


def build_signed_historical_linkage(
    envelope: SignedObjectEnvelope, *, trust_status: str
) -> SignedHistoricalLinkage:
    body = {
        "schema": "omiv.signed-historical-linkage.v1",
        "object_type": envelope.signed_object_type.value,
        "object_id": envelope.signed_object_id,
        "object_digest": envelope.signed_object_digest,
        "envelope_id": envelope.envelope_id,
        "envelope_digest": envelope.envelope_digest,
        "trust_status": trust_status,
        "limitations": [
            "Signature integrity does not upgrade completeness, authority, history, or truth."
        ],
    }
    return SignedHistoricalLinkage.model_validate(
        identified(body, "linkage_id", "signed_history_", "linkage_digest")
    )
