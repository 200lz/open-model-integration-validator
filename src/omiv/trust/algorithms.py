"""Closed Ed25519 adapter; no fallback cryptographic implementation exists."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from omiv.errors import OmivInputError
from omiv.trust.models import SignatureAlgorithm

MAX_KEY_FILE_BYTES = 64 * 1024


def require_ed25519(algorithm: SignatureAlgorithm) -> None:
    if algorithm != SignatureAlgorithm.ED25519:
        raise OmivInputError(f"unsupported signature algorithm: {algorithm.value}")


def raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_from_raw(raw: bytes) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise OmivInputError("malformed Ed25519 public key") from exc


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a bounded, unencrypted PKCS8 PEM without exposing its content."""
    try:
        if path.is_symlink() or not path.is_file():
            raise OmivInputError("private key must be a regular non-symlink file")
        if path.stat().st_size > MAX_KEY_FILE_BYTES:
            raise OmivInputError("private key exceeds the bounded input limit")
        value = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise OmivInputError("private key is not an unencrypted PKCS8 PEM") from exc
    if not isinstance(value, Ed25519PrivateKey):
        raise OmivInputError("private key is not Ed25519")
    return value


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        if path.is_symlink() or not path.is_file():
            raise OmivInputError("public key must be a regular non-symlink file")
        if path.stat().st_size > MAX_KEY_FILE_BYTES:
            raise OmivInputError("public key exceeds the bounded input limit")
        value = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise OmivInputError("public key is not a supported PEM public key") from exc
    if not isinstance(value, Ed25519PublicKey):
        raise OmivInputError("public key is not Ed25519")
    return value


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
