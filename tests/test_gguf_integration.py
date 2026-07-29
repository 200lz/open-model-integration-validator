import importlib.util
import os
from pathlib import Path

import pytest

from omiv.gguf.compare import compare_gguf_inventories
from omiv.gguf.policy import load_gguf_policy
from omiv.gguf.reader import read_gguf_inventory

QWEN_DIR = Path(
    "/home/chen1/projects/llm-inference-optimization-lab/models"
)
FP16 = QWEN_DIR / "qwen2.5-0.5b-instruct-fp16.gguf"
Q8 = QWEN_DIR / "qwen2.5-0.5b-instruct-q8_0.gguf"
Q4 = QWEN_DIR / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
KIMI = Path(
    "/home/chen1/projects/kimi-k3-upstream/llama.cpp/build/tests/"
    "test-models/kimi-linear-moe.gguf"
)
RUN = os.environ.get("OMIV_RUN_GGUF_INTEGRATION") == "1"
HAS_GGUF = importlib.util.find_spec("gguf") is not None


@pytest.mark.integration
@pytest.mark.skipif(not (RUN and HAS_GGUF and FP16.exists()), reason="GGUF integration disabled")
def test_qwen_fp16_inventory() -> None:
    inventory = read_gguf_inventory(FP16)
    assert inventory.header.tensor_count == 291
    assert inventory.identity.architecture == "qwen2"


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and FP16.exists() and Q8.exists()),
    reason="GGUF integration disabled",
)
def test_qwen_q8_comparison() -> None:
    report = compare_gguf_inventories(
        read_gguf_inventory(FP16),
        read_gguf_inventory(Q8),
        load_gguf_policy(Path("policies/qwen2_5_0_5b_fp16_to_q8_0.yaml")),
    )
    assert report.passed


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and FP16.exists() and Q4.exists()),
    reason="GGUF integration disabled",
)
def test_qwen_q4_comparison() -> None:
    report = compare_gguf_inventories(
        read_gguf_inventory(FP16),
        read_gguf_inventory(Q4),
        load_gguf_policy(Path("policies/qwen2_5_0_5b_fp16_to_q4_k_m.yaml")),
    )
    assert report.passed


@pytest.mark.integration
@pytest.mark.skipif(not (RUN and HAS_GGUF and KIMI.exists()), reason="GGUF integration disabled")
def test_synthetic_kimi_linear_reader() -> None:
    inventory = read_gguf_inventory(KIMI)
    assert inventory.identity.architecture == "kimi-linear"
    assert inventory.header.tensor_count == 74
