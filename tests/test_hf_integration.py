import os
from pathlib import Path

import pytest

from omiv.hf.reader import read_hf_inventory

RUN = os.environ.get("OMIV_RUN_HF_INTEGRATION") == "1"
MODEL_DIR_VALUE = os.environ.get("OMIV_QWEN_HF_DIR")
MODEL_DIR = Path(MODEL_DIR_VALUE) if MODEL_DIR_VALUE else None


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and MODEL_DIR is not None and MODEL_DIR.is_dir()),
    reason="HF integration is not configured",
)
def test_real_qwen_hf_inventory() -> None:
    assert MODEL_DIR is not None
    provenance = MODEL_DIR / "omiv-source.json"
    inventory = read_hf_inventory(
        MODEL_DIR,
        provenance_path=provenance if provenance.exists() else None,
    )
    assert inventory.summary.physical_tensor_count == 290
    assert inventory.summary.dtype_counts == {"BF16": 290}
    assert inventory.summary.observed_layer_ids == list(range(24))
    assert inventory.summary.unclassified_tensor_count == 0
    assert len(inventory.logical_ties) == 1
    assert not inventory.logical_ties[0].materialized
