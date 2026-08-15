"""Detached Ed25519 signatures and trust-policy binding for Assurance Bundles."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from omiv.assurance.models import AssuranceSignature, AssuranceTrustPolicy
from omiv.assurance.operations import MANIFEST_NAME, _pretty, load_manifest
from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.safe_write import atomic_write_text
from omiv.trust.algorithms import public_key_from_raw, raw_public_key, sign, verify


def build_signature(root: Path, private_key: Ed25519PrivateKey, key_id: str) -> AssuranceSignature:
    manifest = load_manifest(root / MANIFEST_NAME)
    public = raw_public_key(private_key.public_key())
    body = {
        "schema": "omiv.assurance-signature.v1",
        "algorithm": "ED25519",
        "key_id": key_id,
        "public_key": public.hex(),
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "manifest_digest": manifest.bundle_digest,
        "signature": sign(private_key, manifest.bundle_digest.encode("ascii")).hex(),
        "limitations": [
            "Signature integrity does not establish signer authority without a trust policy."
        ],
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return AssuranceSignature.model_validate(
        {
            **body,
            "signature_id": "assurance_signature_" + digest[:32],
            "signature_digest": digest,
        }
    )


def write_signature(root: Path, signature: AssuranceSignature) -> Path:
    destination = root / "signatures" / f"{signature.key_id}.json"
    atomic_write_text(destination, _pretty(signature))
    return destination


def load_policy(path: Path) -> AssuranceTrustPolicy:
    value, _raw = load_bounded_json(path, max_bytes=1024 * 1024)
    try:
        return AssuranceTrustPolicy.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Assurance Bundle trust policy: {exc}") from exc


def verify_signatures(
    root: Path, policy: AssuranceTrustPolicy | None = None
) -> tuple[int, int, list[str]]:
    manifest = load_manifest(root / MANIFEST_NAME)
    directory = root / "signatures"
    paths = [] if not directory.exists() else sorted(directory.glob("*.json"))
    valid = trusted = 0
    issues: list[str] = []
    for path in paths:
        try:
            value, _raw = load_bounded_json(path, max_bytes=1024 * 1024)
            record = AssuranceSignature.model_validate(value)
            if record.manifest_digest != manifest.bundle_digest:
                raise ValueError("signature manifest digest mismatch")
            public_raw = bytes.fromhex(record.public_key)
            if hashlib.sha256(public_raw).hexdigest() != record.public_key_sha256:
                raise ValueError("signature public-key digest mismatch")
            if not verify(
                public_key_from_raw(public_raw),
                bytes.fromhex(record.signature),
                manifest.bundle_digest.encode("ascii"),
            ):
                raise ValueError("signature verification failed")
            valid += 1
            if policy is not None and (
                (not policy.allowed_key_ids or record.key_id in policy.allowed_key_ids)
                and (
                    not policy.allowed_public_key_sha256
                    or record.public_key_sha256 in policy.allowed_public_key_sha256
                )
            ):
                trusted += 1
        except (OSError, ValidationError, ValueError, OmivInputError) as exc:
            issues.append(f"{path.name}:{exc}")
    if (
        policy is not None
        and policy.require_signature
        and trusted < policy.minimum_valid_signatures
    ):
        issues.append("TRUST_POLICY_MINIMUM_SIGNATURES_NOT_MET")
    return valid, trusted, issues
