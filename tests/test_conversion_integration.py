from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from omiv.hf.reader import pretty_hf_inventory, read_hf_inventory
from omiv.provenance.capture import run_conversion

REQUIRED_ENVIRONMENT = (
    "OMIV_QWEN_HF_DIR",
    "OMIV_LLAMA_CPP_DIR",
    "OMIV_CONVERSION_WORK_DIR",
)


def _configured_conversion_paths() -> tuple[Path, Path, Path]:
    if os.environ.get("OMIV_RUN_CONVERSION_INTEGRATION") != "1":
        pytest.skip("conversion integration disabled")
    values = [os.environ.get(name) for name in REQUIRED_ENVIRONMENT]
    if not all(values):
        pytest.skip("conversion integration paths are not configured")
    source_dir, repository, work_dir = (Path(value) for value in values if value is not None)
    if not source_dir.is_dir() or not repository.is_dir() or not work_dir.is_dir():
        pytest.skip("conversion integration paths are not configured")
    if not os.access(work_dir, os.W_OK):
        pytest.skip("conversion integration work directory is unavailable")
    if not (source_dir / "config.json").is_file() or not any(source_dir.glob("*.safetensors")):
        pytest.skip("configured source model files are unavailable")
    if not (repository / "convert_hf_to_gguf.py").is_file():
        pytest.skip("configured converter entrypoint is absent")
    return source_dir, repository, work_dir


@pytest.mark.parametrize(
    "configured",
    [
        {},
        {name: "" for name in REQUIRED_ENVIRONMENT},
        {"OMIV_QWEN_HF_DIR": "configured"},
        {
            "OMIV_QWEN_HF_DIR": "configured",
            "OMIV_LLAMA_CPP_DIR": "configured",
        },
    ],
)
def test_conversion_integration_requires_explicit_nonempty_paths(
    monkeypatch: pytest.MonkeyPatch, configured: dict[str, str]
) -> None:
    monkeypatch.setenv("OMIV_RUN_CONVERSION_INTEGRATION", "1")
    for name in REQUIRED_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    for name, value in configured.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(pytest.skip.Exception):
        _configured_conversion_paths()


def test_conversion_integration_skips_nonexistent_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OMIV_RUN_CONVERSION_INTEGRATION", "1")
    for name in REQUIRED_ENVIRONMENT:
        monkeypatch.setenv(name, str(tmp_path / "absent"))
    with pytest.raises(pytest.skip.Exception):
        _configured_conversion_paths()


def test_conversion_integration_skips_unavailable_required_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_dir = tmp_path / "source"
    repository = tmp_path / "converter"
    work_dir = tmp_path / "work"
    for path in (source_dir, repository, work_dir):
        path.mkdir()
    monkeypatch.setenv("OMIV_RUN_CONVERSION_INTEGRATION", "1")
    monkeypatch.setenv("OMIV_QWEN_HF_DIR", str(source_dir))
    monkeypatch.setenv("OMIV_LLAMA_CPP_DIR", str(repository))
    monkeypatch.setenv("OMIV_CONVERSION_WORK_DIR", str(work_dir))
    with pytest.raises(pytest.skip.Exception):
        _configured_conversion_paths()


def test_conversion_integration_skips_non_git_converter_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_dir = tmp_path / "source"
    repository = tmp_path / "converter"
    work_dir = tmp_path / "work"
    for path in (source_dir, repository, work_dir):
        path.mkdir()
    (source_dir / "config.json").write_text("{}\n", encoding="utf-8")
    (source_dir / "model.safetensors").write_bytes(b"synthetic")
    (repository / "convert_hf_to_gguf.py").write_text("# synthetic\n", encoding="utf-8")
    monkeypatch.setenv("OMIV_RUN_CONVERSION_INTEGRATION", "1")
    monkeypatch.setenv("OMIV_QWEN_HF_DIR", str(source_dir))
    monkeypatch.setenv("OMIV_LLAMA_CPP_DIR", str(repository))
    monkeypatch.setenv("OMIV_CONVERSION_WORK_DIR", str(work_dir))
    with pytest.raises(pytest.skip.Exception):
        test_opt_in_real_qwen_conversion_capture()


@pytest.mark.integration
def test_opt_in_real_qwen_conversion_capture() -> None:
    source_dir, repository, work_dir = _configured_conversion_paths()
    try:
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
    except subprocess.CalledProcessError:
        pytest.skip("configured converter checkout is unavailable")
    if dirty:
        pytest.skip("configured converter checkout is dirty")
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
