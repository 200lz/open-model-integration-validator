from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.mapping.models import MappingManifest
from omiv.provenance.capture import (
    ConversionRunFailed,
    ConversionRunSpec,
    run_conversion,
)
from omiv.provenance.models import InventoryEvidence, ObservedArtifact


@pytest.fixture(autouse=True)
def _current_python_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    python_directory = str(Path(sys.executable).parent)
    monkeypatch.setenv("PATH", python_directory + os.pathsep + os.environ.get("PATH", ""))


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path, *, exit_code: int = 0) -> tuple[Path, str]:
    repository = tmp_path / "converter"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "test@example.invalid")
    _git(repository, "config", "user.name", "OMIV Test")
    script = repository / "convert.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"if {exit_code}:\n"
        f"    raise SystemExit({exit_code})\n"
        "Path(sys.argv[sys.argv.index('--outfile') + 1]).write_bytes(b'target')\n"
    )
    _git(repository, "add", "convert.py")
    _git(repository, "commit", "-q", "-m", "converter")
    return repository, _git(repository, "rev-parse", "HEAD")


def _manifest() -> MappingManifest:
    return MappingManifest.model_validate(
        {
            "mapping_schema": "omiv.semantic-mapping.v1",
            "mapping_id": "capture-test",
            "model_family": "qwen2",
            "model_pack": {
                "pack_id": "qwen2",
                "pack_schema_version": 1,
                "minimum_pack_version": 1,
            },
            "source_format": "huggingface-safetensors",
            "target_format": "gguf",
            "rules": [
                {
                    "rule_id": "placeholder",
                    "source": {"canonical_identity": "qwen2.token_embedding.weight"},
                    "target": {
                        "canonical_identity": "qwen2.token_embedding.weight",
                        "tensor_name": "token_embd.weight",
                    },
                    "source_kind": "physical",
                    "cardinality": "one_to_one",
                    "shape_relation": "reverse_dimensions",
                    "payload_transform": "identity",
                    "parameter": "weight",
                }
            ],
        }
    )


def _spec(
    tmp_path: Path,
    repository: Path,
    revision: str,
    *,
    secret: bool = False,
) -> dict[str, Any]:
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    inventory = tmp_path / "source-inventory.json"
    inventory.write_text("{}")
    mapping = tmp_path / "mapping.json"
    mapping.write_text("{}")
    config = source_dir / "config.json"
    config.write_text("{}")
    arguments = [
        "{source_model_dir}",
        "--outfile",
        "{target_output}",
    ]
    if secret:
        arguments.extend(["--token", "secret-value"])
    return {
        "conversion_schema": "omiv.conversion-run.v1",
        "conversion_id": "capture-test",
        "offline": True,
        "source": {
            "model_dir": str(source_dir),
            "inventory": str(inventory),
            "artifact_roles": [
                {"role": "config", "path": str(config), "required": True}
            ],
        },
        "interpretation": {"model_pack": "qwen2", "mapping": str(mapping)},
        "tool": {
            "name": "synthetic-converter",
            "repository": "example/converter",
            "repository_dir": str(repository),
            "expected_revision": revision,
            "require_clean_worktree": True,
            "executable": Path(sys.executable).name,
            "entrypoint": "convert.py",
        },
        "invocation": {"arguments": arguments},
        "target": {
            "output": str(tmp_path / "target.gguf"),
            "format": "gguf",
            "inventory_output": str(tmp_path / "target.inventory.json"),
            "role": "model",
        },
        "outputs": {
            "provenance": str(tmp_path / "provenance.json"),
            "report_json": str(tmp_path / "report.json"),
            "report_markdown": str(tmp_path / "report.md"),
        },
    }


def _patch_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = tmp_path / "source" / "config.json"
    config_digest = hashlib.sha256(config.read_bytes()).hexdigest()
    source = InventoryEvidence(
        format="huggingface-safetensors",
        inventory_schema="omiv.hf-inventory.v1",
        inventory_sha256="a" * 64,
        model_family="qwen2",
        repository="example/qwen",
        revision="c" * 40,
        artifacts={
            "config": ObservedArtifact(
                artifact_id="config.json",
                byte_size=config.stat().st_size,
                sha256=config_digest,
                full_artifact_digest=True,
            )
        },
    )
    monkeypatch.setattr(
        "omiv.provenance.capture.load_inventory_evidence",
        lambda path: source,
    )
    monkeypatch.setattr(
        "omiv.provenance.capture.load_mapping_manifest",
        lambda path, requested_pack_id: _manifest(),
    )

    def generate(format_id: str, artifact: Path) -> tuple[dict[str, Any], InventoryEvidence]:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        value = {"synthetic": True}
        return value, InventoryEvidence(
            format="gguf",
            inventory_schema="omiv.gguf-inventory.v1",
            inventory_sha256=canonical_sha256(value),
            model_family="qwen2",
            architecture="qwen2",
            artifacts={
                artifact.name: ObservedArtifact(
                    artifact_id=artifact.name,
                    byte_size=artifact.stat().st_size,
                    sha256=digest,
                    full_artifact_digest=True,
                )
            },
        )

    monkeypatch.setattr(
        "omiv.provenance.capture.generate_target_inventory",
        generate,
    )


def test_capture_uses_argument_array_and_redacts_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, revision = _repository(tmp_path)
    spec = _spec(tmp_path, repository, revision, secret=True)
    spec_path = tmp_path / "conversion.json"
    spec_path.write_text(json.dumps(spec))
    _patch_evidence(monkeypatch, tmp_path)

    provenance = run_conversion(spec_path)

    assert provenance.process.result.success
    assert provenance.process.invocation.arguments[-2:] == [
        "--token",
        "[REDACTED]",
    ]
    assert "secret-value" not in (tmp_path / "provenance.json").read_text()
    assert (tmp_path / "target.inventory.json").exists()
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.md").exists()


def test_capture_records_only_explicit_python_runtime_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, revision = _repository(tmp_path)
    spec = _spec(tmp_path, repository, revision)
    spec["runtime"] = {"python": True, "packages": ["pydantic"]}
    spec_path = tmp_path / "conversion.json"
    spec_path.write_text(json.dumps(spec))
    _patch_evidence(monkeypatch, tmp_path)

    provenance = run_conversion(spec_path)

    assert provenance.process.runtime is not None
    assert provenance.process.runtime.python_version == platform.python_version()
    assert provenance.process.runtime.package_versions == {
        "pydantic": importlib.metadata.version("pydantic")
    }


def test_process_failure_emits_no_success_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, revision = _repository(tmp_path, exit_code=7)
    spec = _spec(tmp_path, repository, revision)
    spec_path = tmp_path / "conversion.json"
    spec_path.write_text(json.dumps(spec))
    _patch_evidence(monkeypatch, tmp_path)

    with pytest.raises(ConversionRunFailed) as captured:
        run_conversion(spec_path)

    assert captured.value.exit_code == 7
    assert not (tmp_path / "provenance.json").exists()
    assert not (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.md").exists()


def test_capture_rejects_unknown_placeholder_output_collision_and_symlink(
    tmp_path: Path,
) -> None:
    repository, revision = _repository(tmp_path)
    raw = _spec(tmp_path, repository, revision)
    raw["invocation"]["arguments"] = ["{unknown}"]
    with pytest.raises(ValueError, match="unsupported placeholder"):
        ConversionRunSpec.model_validate(raw)
    raw = _spec(tmp_path, repository, revision)
    raw["invocation"]["arguments"] = ["$(touch unsafe)"]
    with pytest.raises(ValueError, match="shell interpolation"):
        ConversionRunSpec.model_validate(raw)
    raw = _spec(tmp_path, repository, revision)
    raw["invocation"]["arguments"] = ["--remote"]
    with pytest.raises(ValueError, match="network"):
        ConversionRunSpec.model_validate(raw)
    raw = _spec(tmp_path, repository, revision)
    raw["tool"]["entrypoint"] = "../convert.py"
    with pytest.raises(ValueError, match="relative"):
        ConversionRunSpec.model_validate(raw)
    raw = _spec(tmp_path, repository, revision)
    raw["runtime"] = {"python": True, "packages": ["unsafe package"]}
    with pytest.raises(ValueError, match="package name"):
        ConversionRunSpec.model_validate(raw)
    raw = _spec(tmp_path, repository, revision)
    raw["runtime"] = {"python": True, "packages": ["torch", "torch"]}
    with pytest.raises(ValueError, match="unique"):
        ConversionRunSpec.model_validate(raw)

    raw = _spec(tmp_path, repository, revision)
    raw["target"]["output"] = raw["source"]["inventory"]
    spec_path = tmp_path / "collision.json"
    spec_path.write_text(json.dumps(raw))
    with pytest.raises(OmivInputError, match="collides"):
        run_conversion(spec_path)

    raw = _spec(tmp_path, repository, revision)
    symlink = tmp_path / "target.gguf"
    symlink.symlink_to(tmp_path / "elsewhere")
    spec_path = tmp_path / "symlink.json"
    spec_path.write_text(json.dumps(raw))
    with pytest.raises(OmivInputError, match="symlink"):
        run_conversion(spec_path)


def test_capture_rejects_head_mismatch_and_dirty_repository(tmp_path: Path) -> None:
    repository, revision = _repository(tmp_path)
    raw = _spec(tmp_path, repository, "f" * 40)
    spec_path = tmp_path / "wrong-head.json"
    spec_path.write_text(json.dumps(raw))
    with pytest.raises(OmivInputError, match="HEAD"):
        run_conversion(spec_path)

    raw = _spec(tmp_path, repository, revision)
    (repository / "convert.py").write_text("# dirty\n")
    spec_path = tmp_path / "dirty.json"
    spec_path.write_text(json.dumps(raw))
    with pytest.raises(OmivInputError, match="dirty"):
        run_conversion(spec_path)
