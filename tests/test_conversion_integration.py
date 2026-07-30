from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from omiv.hf.reader import pretty_hf_inventory, read_hf_inventory
from omiv.provenance.capture import run_conversion


@pytest.mark.integration
def test_opt_in_real_qwen_conversion_capture() -> None:
    if os.environ.get("OMIV_RUN_CONVERSION_INTEGRATION") != "1":
        pytest.skip("conversion integration disabled")
    source_dir = Path(
        os.environ.get(
            "OMIV_QWEN_HF_DIR",
            "/home/chen1/models/huggingface/Qwen2.5-0.5B-Instruct",
        )
    )
    repository = Path(os.environ.get("OMIV_LLAMA_CPP_DIR", ""))
    work_dir = Path(os.environ.get("OMIV_CONVERSION_WORK_DIR", ""))
    if not source_dir.is_dir() or not repository.is_dir() or not work_dir.is_dir():
        pytest.skip("conversion integration paths are not configured")
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        pytest.skip("configured converter checkout is dirty")
    entrypoint = repository / "convert_hf_to_gguf.py"
    if not entrypoint.is_file():
        pytest.skip("configured converter entrypoint is absent")

    inventory_path = work_dir / "qwen-source.inventory.json"
    target_path = work_dir / "qwen-f16.phase4d.gguf"
    target_inventory = work_dir / "qwen-f16.phase4d.inventory.json"
    provenance_path = work_dir / "qwen-f16.phase4d.provenance.json"
    report_path = work_dir / "qwen-f16.phase4d.report.json"
    markdown_path = work_dir / "qwen-f16.phase4d.report.md"
    spec_path = work_dir / "qwen-f16.phase4d.conversion.json"
    outputs = (
        target_path,
        target_inventory,
        provenance_path,
        report_path,
        markdown_path,
        spec_path,
    )
    if any(path.exists() for path in outputs):
        pytest.skip("conversion integration outputs already exist")
    inventory_path.write_text(
        pretty_hf_inventory(read_hf_inventory(source_dir)),
        encoding="utf-8",
    )
    artifacts = [
        {
            "role": "config",
            "path": str(source_dir / "config.json"),
            "required": True,
        }
    ]
    index = source_dir / "model.safetensors.index.json"
    if index.exists():
        artifacts.append({"role": "index", "path": str(index), "required": True})
    artifacts.extend(
        {
            "role": f"checkpoint-shard-{number:05d}",
            "path": str(path),
            "required": True,
        }
        for number, path in enumerate(sorted(source_dir.glob("*.safetensors")))
    )
    spec = {
        "conversion_schema": "omiv.conversion-run.v1",
        "conversion_id": "qwen2.5-0.5b-instruct-f16",
        "offline": True,
        "source": {
            "model_dir": str(source_dir),
            "inventory": str(inventory_path),
            "artifact_roles": artifacts,
        },
        "interpretation": {
            "model_pack": "qwen2",
            "mapping": "mappings/qwen2_5_0_5b_hf_to_gguf.yaml",
        },
        "tool": {
            "name": "llama.cpp",
            "repository": "ggml-org/llama.cpp",
            "repository_dir": str(repository),
            "expected_revision": head,
            "require_clean_worktree": True,
            "executable": "python",
            "entrypoint": "convert_hf_to_gguf.py",
        },
        "invocation": {
            "arguments": [
                "{source_model_dir}",
                "--outfile",
                "{target_output}",
                "--outtype",
                "f16",
            ]
        },
        "target": {
            "output": str(target_path),
            "format": "gguf",
            "inventory_output": str(target_inventory),
            "role": "model",
        },
        "outputs": {
            "provenance": str(provenance_path),
            "report_json": str(report_path),
            "report_markdown": str(markdown_path),
        },
    }
    spec_path.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    provenance = run_conversion(spec_path)
    assert provenance.provenance_id == "qwen2.5-0.5b-instruct-f16"
    assert target_path.is_file()
    assert provenance_path.is_file()
