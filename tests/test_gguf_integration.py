import importlib.util
import os
from pathlib import Path

import pytest

from omiv.gguf.compare import compare_gguf_inventories
from omiv.gguf.policy import load_gguf_policy
from omiv.gguf.reader import read_gguf_inventory


def _path_from_env(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


QWEN_DIR = _path_from_env("OMIV_QWEN_GGUF_DIR")
FP16 = QWEN_DIR / "qwen2.5-0.5b-instruct-fp16.gguf" if QWEN_DIR else None
Q8 = QWEN_DIR / "qwen2.5-0.5b-instruct-q8_0.gguf" if QWEN_DIR else None
Q4 = QWEN_DIR / "qwen2.5-0.5b-instruct-q4_k_m.gguf" if QWEN_DIR else None
KIMI = _path_from_env("OMIV_KIMI_LINEAR_GGUF")
RUN = os.environ.get("OMIV_RUN_GGUF_INTEGRATION") == "1"
HAS_GGUF = importlib.util.find_spec("gguf") is not None


def _files_exist(*paths: Path | None) -> bool:
    return all(path is not None and path.is_file() for path in paths)


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and _files_exist(FP16)),
    reason="GGUF integration disabled or file not configured/found",
)
def test_qwen_fp16_inventory() -> None:
    assert FP16 is not None
    inventory = read_gguf_inventory(FP16)
    assert inventory.header.tensor_count == 291
    assert inventory.identity.architecture == "qwen2"


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and _files_exist(FP16, Q8)),
    reason="GGUF integration disabled or files not configured/found",
)
def test_qwen_q8_comparison() -> None:
    assert FP16 is not None
    assert Q8 is not None
    report = compare_gguf_inventories(
        read_gguf_inventory(FP16),
        read_gguf_inventory(Q8),
        load_gguf_policy(Path("policies/qwen2_5_0_5b_fp16_to_q8_0.yaml")),
    )
    assert report.passed


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and _files_exist(FP16, Q4)),
    reason="GGUF integration disabled or files not configured/found",
)
def test_qwen_q4_comparison() -> None:
    assert FP16 is not None
    assert Q4 is not None
    report = compare_gguf_inventories(
        read_gguf_inventory(FP16),
        read_gguf_inventory(Q4),
        load_gguf_policy(Path("policies/qwen2_5_0_5b_fp16_to_q4_k_m.yaml")),
    )
    assert report.passed


@pytest.mark.integration
@pytest.mark.skipif(
    not (RUN and HAS_GGUF and _files_exist(KIMI)),
    reason="GGUF integration disabled or file not configured/found",
)
def test_synthetic_kimi_linear_reader() -> None:
    assert KIMI is not None
    inventory = read_gguf_inventory(KIMI)
    assert inventory.identity.architecture == "kimi-linear"
    assert inventory.header.tensor_count == 74
