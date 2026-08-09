"""Deterministic identity-bound sampling for Phase 6C."""

from __future__ import annotations

import hashlib

from omiv.quantization.models import DeterministicSampleDefinition, finalize_identity

MAX_SAMPLE_POPULATION = 1_000_000_000
MAX_SAMPLE_COUNT = 100_000
MAX_SAMPLE_HASH_ATTEMPTS = MAX_SAMPLE_COUNT * 128
MAX_POPULATION_TRAVERSAL = MAX_SAMPLE_COUNT


def build_sample_definition(
    *,
    seed: str,
    source_tensor_id: str,
    candidate_tensor_id: str,
    population_count: int,
    requested_count: int,
    maximum_count: int,
) -> DeterministicSampleDefinition:
    """Select deterministic unique indices without host randomness or Python hash()."""
    if population_count < 0 or requested_count < 0 or maximum_count < 0:
        raise ValueError("sample counts cannot be negative")
    if maximum_count > MAX_SAMPLE_COUNT:
        raise ValueError("LIMIT_EXCEEDED:MAXIMUM_SAMPLE_COUNT")
    status = "AVAILABLE"
    selected: tuple[int, ...]
    attempts = 0
    if population_count > MAX_SAMPLE_POPULATION or requested_count > maximum_count:
        status = "LIMIT_EXCEEDED"
        selected = ()
    elif population_count == 0 or requested_count == 0:
        status = "EMPTY"
        selected = ()
    else:
        actual = min(population_count, requested_count)
        if actual == population_count:
            selected = tuple(range(population_count))
        else:
            chosen: set[int] = set()
            counter = 0
            # Rejection is bounded. The limit is deliberately generous for the supported
            # sample-to-population ratios while remaining deterministic on adversarial inputs.
            maximum_attempts = min(MAX_SAMPLE_HASH_ATTEMPTS, max(1024, actual * 128))
            prefix = (
                "omiv.quantization.sample.sha256-rejection.v1\0"
                f"{seed}\0{source_tensor_id}\0{candidate_tensor_id}\0{population_count}\0"
            ).encode()
            while len(chosen) < actual and counter < maximum_attempts:
                digest = hashlib.sha256(prefix + str(counter).encode("ascii")).digest()
                chosen.add(int.from_bytes(digest, "big") % population_count)
                counter += 1
            attempts = counter
            if len(chosen) != actual:
                status = "LIMIT_EXCEEDED"
                selected = ()
            else:
                selected = tuple(sorted(chosen))
    body = {
        "schema": "omiv.deterministic-sample-definition.v1",
        "algorithm": "SHA256_REJECTION_V1",
        "domain_separated_seed": seed,
        "source_tensor_id": source_tensor_id,
        "candidate_tensor_id": candidate_tensor_id,
        "population_element_count": population_count,
        "requested_sample_count": requested_count,
        "actual_sample_count": len(selected),
        "selected_indices": selected,
        "ordering": "ASCENDING_INDEX",
        "inclusion_rules": ("IDENTITY_BOUND_HASH_DERIVATION",),
        "exclusion_rules": ("DUPLICATE_DERIVED_INDICES_REJECTED",),
        "maximum_sample_count": maximum_count,
        "maximum_population_count": MAX_SAMPLE_POPULATION,
        "maximum_population_traversal_count": MAX_POPULATION_TRAVERSAL,
        "maximum_hash_attempts": MAX_SAMPLE_HASH_ATTEMPTS,
        "hash_attempt_count": attempts,
        "maximum_stored_candidates": MAX_SAMPLE_COUNT,
        "status": status,
        "limitations": (
            "Deterministic selection is reproducible but is not claimed statistically "
            "representative. Rejection sampling stores at most 100000 candidates and performs "
            "at most 12800000 hashes; full population traversal is limited to 100000 elements.",
        ),
    }
    return DeterministicSampleDefinition.model_validate(
        finalize_identity(body, "sample_id", "quantization_sample_", "sample_digest")
    )
