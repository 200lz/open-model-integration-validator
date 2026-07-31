"""Generic artifact acquisition and transformation attestations."""

from omiv.attestations.builder import build_attestation
from omiv.attestations.verification import verify_attestation

__all__ = ["build_attestation", "verify_attestation"]
