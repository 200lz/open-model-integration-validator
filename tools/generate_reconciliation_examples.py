"""Generate deterministic offline Phase 6B reconciliation artifacts."""

from pathlib import Path

from omiv.reconciliation_profiles.examples import generate_all_reconciliation_examples

if __name__ == "__main__":
    generate_all_reconciliation_examples(Path.cwd())
