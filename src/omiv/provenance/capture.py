"""Conservative shell-free conversion capture from a strict specification."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from omiv import __version__
from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.mapping.manifest import load_mapping_manifest
from omiv.model_packs.registry import get_model_pack
from omiv.provenance.adapters import (
    generate_target_inventory,
    load_inventory_evidence,
)
from omiv.provenance.loading import load_model
from omiv.provenance.models import (
    REDACTION_MARKER,
    SENSITIVE_ARGUMENTS,
    ArtifactDigestEvidence,
    ArtifactIdentity,
    CaptureMetadata,
    ConversionProvenance,
    InterpretationModelPack,
    InterpretationProvenance,
    Invocation,
    MappingIdentity,
    ModelPackIdentity,
    Operation,
    ProcessProvenance,
    ProcessResult,
    RevisionKind,
    RuntimeIdentity,
    SourceProvenance,
    StrictModel,
    TargetArtifact,
    TargetProvenance,
    ToolIdentity,
    ToolSourceIdentity,
)
from omiv.provenance.reporting import (
    build_provenance_envelope,
    build_provenance_report_envelope,
    pretty_provenance_json,
    pretty_provenance_report_json,
    render_provenance_markdown,
)
from omiv.provenance.validator import ProvenanceValidationContext, validate_provenance
from omiv.safe_write import atomic_write_text, validate_output_path

ALLOWED_PLACEHOLDERS = frozenset({"{source_model_dir}", "{target_output}"})


class ConversionRunFailed(RuntimeError):
    def __init__(self, exit_code: int) -> None:
        super().__init__(f"conversion process failed with exit code {exit_code}")
        self.exit_code = exit_code


class SourceArtifactSpec(StrictModel):
    role: str = Field(min_length=1, max_length=128)
    path: Path
    required: bool = True


class ConversionSourceSpec(StrictModel):
    model_dir: Path
    inventory: Path
    artifact_roles: list[SourceArtifactSpec] = Field(min_length=1, max_length=10000)


class ConversionInterpretationSpec(StrictModel):
    model_pack: str = Field(min_length=1, max_length=128)
    mapping: Path


class ConversionToolSpec(StrictModel):
    name: str = Field(default="conversion-tool", min_length=1, max_length=256)
    repository: str | None = Field(default=None, min_length=1, max_length=1000)
    repository_dir: Path
    expected_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    require_clean_worktree: bool = True
    executable: str = Field(min_length=1, max_length=128)
    entrypoint: str = Field(min_length=1, max_length=512)

    @field_validator("executable")
    @classmethod
    def executable_is_name(cls, value: str) -> str:
        if "/" in value or "\\" in value:
            raise ValueError("executable must be a command name")
        return value

    @field_validator("entrypoint")
    @classmethod
    def entrypoint_is_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError("entrypoint must be a safe relative path")
        return value


class ConversionRuntimeSpec(StrictModel):
    python: Literal[True]
    packages: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("packages")
    @classmethod
    def package_names_are_safe_and_unique(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("runtime package names must be unique")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) for value in values):
            raise ValueError("runtime package name is invalid")
        return values


class ConversionInvocationSpec(StrictModel):
    arguments: list[str] = Field(max_length=10000)

    @field_validator("arguments")
    @classmethod
    def placeholders_are_explicit(cls, values: list[str]) -> list[str]:
        for value in values:
            cursor = value
            for placeholder in ALLOWED_PLACEHOLDERS:
                cursor = cursor.replace(placeholder, "")
            if "{" in cursor or "}" in cursor:
                raise ValueError("invocation contains an unsupported placeholder")
            if any(token in value for token in ("$(", "${", "`", "\0")):
                raise ValueError("invocation contains shell interpolation syntax")
            if value == "--remote" or value.startswith(("http://", "https://")):
                raise ValueError("offline conversion cannot request network access")
        return values


class ConversionTargetSpec(StrictModel):
    output: Path
    format: str = Field(min_length=1, max_length=128)
    inventory_output: Path
    role: str = Field(default="model", min_length=1, max_length=128)
    artifact_type: str | None = Field(default=None, max_length=128)


class ConversionOutputSpec(StrictModel):
    provenance: Path
    report_json: Path
    report_markdown: Path


class ConversionRunSpec(StrictModel):
    conversion_schema: Literal["omiv.conversion-run.v1"]
    conversion_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    )
    operation: Operation = Operation.CONVERT
    offline: Literal[True]
    source: ConversionSourceSpec
    interpretation: ConversionInterpretationSpec
    tool: ConversionToolSpec
    runtime: ConversionRuntimeSpec | None = None
    invocation: ConversionInvocationSpec
    target: ConversionTargetSpec
    outputs: ConversionOutputSpec

    @model_validator(mode="after")
    def unique_source_roles(self) -> ConversionRunSpec:
        roles = [item.role for item in self.source.artifact_roles]
        if len(roles) != len(set(roles)):
            raise ValueError("source artifact roles must be unique")
        return self


def load_conversion_spec(path: Path) -> ConversionRunSpec:
    return load_model(path, ConversionRunSpec, label="conversion spec")


def _git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        raise OmivInputError(f"cannot inspect conversion tool repository: {exc}") from exc
    if result.returncode != 0:
        raise OmivInputError("conversion tool repository inspection failed")
    return result.stdout[: 1024 * 1024].strip()


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
    except OSError as exc:
        raise OmivInputError(f"cannot hash artifact {path.name}: {exc}") from exc
    return size, digest.hexdigest()


def _capture_python_runtime(
    executable: str,
    runtime: ConversionRuntimeSpec | None,
) -> RuntimeIdentity | None:
    if runtime is None:
        return None
    probe = (
        "import importlib.metadata,json,platform,sys;"
        "print(json.dumps({'python_version':platform.python_version(),"
        "'package_versions':{name:importlib.metadata.version(name)"
        " for name in sys.argv[1:]}},sort_keys=True))"
    )
    try:
        result = subprocess.run(
            [executable, "-c", probe, *runtime.packages],
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as exc:
        raise OmivInputError(f"cannot inspect conversion runtime: {exc}") from exc
    if result.returncode != 0:
        raise OmivInputError("conversion runtime inspection failed")
    if len(result.stdout) > 64 * 1024:
        raise OmivInputError("conversion runtime inspection output is too large")
    try:
        value = json.loads(result.stdout)
        return RuntimeIdentity.model_validate(value)
    except (json.JSONDecodeError, ValueError) as exc:
        raise OmivInputError("conversion runtime inspection returned invalid data") from exc


def _reject_existing_output(path: Path) -> None:
    validate_output_path(path)
    if path.exists():
        raise OmivInputError(f"conversion output already exists: {path.name}")


def _redact_arguments(arguments: list[str]) -> tuple[list[str], list[str]]:
    redacted = list(arguments)
    names: set[str] = set()
    index = 0
    while index < len(redacted):
        name, separator, _ = redacted[index].partition("=")
        if name in SENSITIVE_ARGUMENTS:
            names.add(name)
            if separator:
                redacted[index] = f"{name}={REDACTION_MARKER}"
            else:
                if index + 1 >= len(redacted):
                    raise OmivInputError(f"sensitive argument {name} has no value")
                redacted[index + 1] = REDACTION_MARKER
                index += 1
        index += 1
    return redacted, sorted(names)


def _resolved_arguments(spec: ConversionRunSpec) -> list[str]:
    replacements = {
        "{source_model_dir}": str(spec.source.model_dir.resolve()),
        "{target_output}": str(spec.target.output.resolve()),
    }
    return [
        argument.replace("{source_model_dir}", replacements["{source_model_dir}"]).replace(
            "{target_output}", replacements["{target_output}"]
        )
        for argument in spec.invocation.arguments
    ]


def _validate_paths(spec_path: Path, spec: ConversionRunSpec) -> tuple[Path, Path]:
    repository = spec.tool.repository_dir.resolve(strict=True)
    entrypoint = (repository / spec.tool.entrypoint).resolve(strict=True)
    try:
        entrypoint.relative_to(repository)
    except ValueError as exc:
        raise OmivInputError("tool entrypoint resolves outside repository") from exc
    if not entrypoint.is_file() or entrypoint.is_symlink():
        raise OmivInputError("tool entrypoint must be a regular non-symlink file")
    inputs = {
        spec_path.resolve(),
        spec.source.inventory.resolve(),
        spec.interpretation.mapping.resolve(),
        *(item.path.resolve() for item in spec.source.artifact_roles),
    }
    outputs = [
        spec.target.output,
        spec.target.inventory_output,
        spec.outputs.provenance,
        spec.outputs.report_json,
        spec.outputs.report_markdown,
    ]
    resolved_outputs = [item.resolve(strict=False) for item in outputs]
    if len(resolved_outputs) != len(set(resolved_outputs)):
        raise OmivInputError("conversion outputs must be distinct")
    if any(item in inputs for item in resolved_outputs):
        raise OmivInputError("conversion output collides with an input")
    for output in outputs:
        _reject_existing_output(output)
    return repository, entrypoint


def run_conversion(spec_path: Path) -> ConversionProvenance:
    """Execute a validated conversion spec and emit provenance only after validation."""
    spec = load_conversion_spec(spec_path)
    repository, entrypoint = _validate_paths(spec_path, spec)
    head = _git(repository, "rev-parse", "HEAD")
    if head != spec.tool.expected_revision:
        raise OmivInputError("conversion tool repository HEAD does not match expected revision")
    dirty = bool(_git(repository, "status", "--porcelain", "--untracked-files=normal"))
    if spec.tool.require_clean_worktree and dirty:
        raise OmivInputError("conversion tool repository has a dirty working tree")
    executable = shutil.which(spec.tool.executable)
    if executable is None:
        raise OmivInputError(f"conversion executable not found: {spec.tool.executable}")
    runtime = _capture_python_runtime(executable, spec.runtime)

    source_inventory = load_inventory_evidence(spec.source.inventory)
    pack = get_model_pack(spec.interpretation.model_pack)
    manifest = load_mapping_manifest(
        spec.interpretation.mapping,
        requested_pack_id=pack.pack_id,
    )
    source_artifacts: list[ArtifactIdentity] = []
    source_paths: dict[str, Path] = {}
    for item in spec.source.artifact_roles:
        path = item.path.resolve(strict=True)
        if not path.is_file() or path.is_symlink():
            raise OmivInputError(f"source artifact {item.role} is not a regular file")
        size, digest = _hash_file(path)
        source_paths[item.role] = path
        source_artifacts.append(
            ArtifactIdentity(
                role=item.role,
                artifact_id=path.name,
                byte_size=size,
                sha256=digest,
                required=item.required,
                digest_evidence=ArtifactDigestEvidence.FULL_ARTIFACT,
            )
        )

    runtime_arguments = _resolved_arguments(spec)
    canonical_arguments, redacted_names = _redact_arguments(spec.invocation.arguments)
    result = subprocess.run(
        [executable, str(entrypoint), *runtime_arguments],
        cwd=repository,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise ConversionRunFailed(result.returncode)
    if not spec.target.output.is_file() or spec.target.output.is_symlink():
        raise OmivInputError("successful conversion did not create a regular target file")
    post_head = _git(repository, "rev-parse", "HEAD")
    post_dirty = bool(
        _git(repository, "status", "--porcelain", "--untracked-files=normal")
    )
    if post_head != head:
        raise OmivInputError("conversion tool repository HEAD changed during execution")
    if spec.tool.require_clean_worktree and post_dirty:
        raise OmivInputError("conversion tool repository became dirty during execution")

    target_value, target_inventory = generate_target_inventory(
        spec.target.format,
        spec.target.output,
    )
    target_size, target_digest = _hash_file(spec.target.output)
    target_artifact = TargetArtifact(
        role=spec.target.role,
        artifact_id=spec.target.output.name,
        sha256=target_digest,
        byte_size=target_size,
        output_success=True,
    )
    provenance = ConversionProvenance(
        provenance_schema="omiv.conversion-provenance.v1",
        provenance_id=spec.conversion_id,
        operation=spec.operation,
        source=SourceProvenance(
            format=source_inventory.format,
            inventory_schema=source_inventory.inventory_schema,
            inventory_sha256=source_inventory.inventory_sha256,
            model_family=source_inventory.model_family or manifest.model_family,
            model_pack=ModelPackIdentity(
                pack_id=pack.pack_id,
                pack_version=pack.pack_version,
                metadata_sha256=pack.metadata.digest,
            ),
            repository=source_inventory.repository,
            revision=source_inventory.revision,
            artifacts=source_artifacts,
        ),
        interpretation=InterpretationProvenance(
            model_pack=InterpretationModelPack(
                pack_id=pack.pack_id,
                pack_schema_version=pack.pack_schema_version,
                pack_version=pack.pack_version,
                metadata_sha256=pack.metadata.digest,
            ),
            mapping=MappingIdentity(
                mapping_schema=manifest.mapping_schema,
                mapping_id=manifest.mapping_id,
                canonical_sha256=canonical_sha256(manifest.model_dump(mode="json")),
            ),
        ),
        process=ProcessProvenance(
            operation=spec.operation,
            tool=ToolIdentity(
                name=spec.tool.name,
                repository=spec.tool.repository,
                revision=head,
                revision_kind=RevisionKind.GIT_COMMIT,
                entrypoint=spec.tool.entrypoint,
            ),
            invocation=Invocation(
                executable=spec.tool.executable,
                arguments=canonical_arguments,
                working_tree_policy=(
                    "require_clean" if spec.tool.require_clean_worktree else "allow_dirty"
                ),
                redacted_arguments=redacted_names,
            ),
            result=ProcessResult(exit_code=0, success=True),
            declared_outputs=[spec.target.role],
            runtime=runtime,
            tool_source=ToolSourceIdentity(
                clean_worktree=not dirty,
                repository_head=head,
            ),
        ),
        target=TargetProvenance(
            format=target_inventory.format,
            inventory_schema=target_inventory.inventory_schema,
            inventory_sha256=target_inventory.inventory_sha256,
            architecture=target_inventory.architecture,
            artifact_type=spec.target.artifact_type,
            artifacts=[target_artifact],
        ),
        capture=CaptureMetadata(
            tool_name="open-model-integration-validator",
            omiv_version=__version__,
            capture_schema_version=1,
            redaction_count=len(redacted_names),
            offline=True,
            payload_access="full_file_hashing",
            artifact_hashing="requested_full_sha256",
        ),
    )
    validation = validate_provenance(
        provenance,
        ProvenanceValidationContext(
            source_inventory=source_inventory,
            target_inventory=target_inventory,
            mapping=manifest,
            model_pack=pack,
            source_artifacts=source_paths,
            target_artifacts={spec.target.role: spec.target.output},
            observed_tool_head=head,
        ),
    )
    if not validation.passed:
        raise OmivInputError("captured provenance failed validation")

    provenance_envelope = build_provenance_envelope(provenance)
    report_envelope = build_provenance_report_envelope(provenance, validation)
    inputs = (
        spec_path,
        spec.source.inventory,
        spec.interpretation.mapping,
        *(item.path for item in spec.source.artifact_roles),
        spec.target.output,
    )
    atomic_write_text(
        spec.target.inventory_output,
        json.dumps(target_value, indent=2, sort_keys=True) + "\n",
        forbidden_inputs=inputs,
    )
    atomic_write_text(
        spec.outputs.provenance,
        pretty_provenance_json(provenance_envelope),
        forbidden_inputs=inputs,
    )
    atomic_write_text(
        spec.outputs.report_json,
        pretty_provenance_report_json(report_envelope),
        forbidden_inputs=inputs,
    )
    atomic_write_text(
        spec.outputs.report_markdown,
        render_provenance_markdown(report_envelope),
        forbidden_inputs=inputs,
    )
    return provenance
