"""Smoke tests for the approved Phase 5D cryptographic dependency."""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_ed25519_in_memory_sign_verify_and_tamper_rejection() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    message = b"omiv-phase-5d-dependency-smoke-test"

    signature = private_key.sign(message)

    assert len(signature) == 64
    public_key.verify(signature, message)
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, message + b"-tampered")
