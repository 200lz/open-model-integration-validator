from pathlib import Path

import pytest

from omiv.normalizer import normalize_inventory
from omiv.schema.loader import load_schema
from omiv.validators.kimi_k3 import validate_inventory

RAW = Path("reports/raw/kimi_k3_tensors.json")


@pytest.mark.integration
@pytest.mark.skipif(not RAW.exists(), reason="local Kimi K3 raw inventory is absent")
def test_real_kimi_k3_inventory() -> None:
    inventory = normalize_inventory(RAW)
    report = validate_inventory(inventory, load_schema(Path("schemas/kimi_k3.yaml")))
    assert inventory.source.record_count == 497_220
    assert report.passed
