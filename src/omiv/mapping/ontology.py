"""Model-independent semantic views over canonical format inventories."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory, GGUFTensorDescriptor
from omiv.hf.models import HFInventory
from omiv.mapping.models import SemanticTensorDescriptor, SourceKind
from omiv.model_packs.base import ModelPack, TensorClassification


def _target_descriptor(tensor: GGUFTensorDescriptor, pack: ModelPack) -> SemanticTensorDescriptor:
    canonical = pack.classify_gguf_tensor(tensor.name).canonical
    return SemanticTensorDescriptor(
        exact_name=tensor.name,
        canonical_identity=None if canonical is None else canonical.identity,
        classification="unclassified" if canonical is None else "classified",
        scope=None if canonical is None else canonical.scope,
        layer_id=None if canonical is None else canonical.layer_id,
        module=None if canonical is None else canonical.module,
        component=None if canonical is None else canonical.component,
        parameter=None if canonical is None else canonical.parameter,
        source_kind=SourceKind.PHYSICAL,
        materialized=True,
        shape=tensor.shape,
        shape_order="gguf_on_disk_reader_tensor_shape",
        data_type=tensor.ggml_type,
    )


def gguf_semantic_view(inventory: GGUFInventory, pack: ModelPack) -> list[SemanticTensorDescriptor]:
    """Classify raw GGUF descriptors using the selected model pack."""
    descriptors = [_target_descriptor(tensor, pack) for tensor in inventory.tensors]
    classified = [
        item.canonical_identity for item in descriptors if item.canonical_identity is not None
    ]
    duplicates = sorted(identity for identity in set(classified) if classified.count(identity) > 1)
    if duplicates:
        raise OmivInputError("duplicate GGUF canonical identities: " + ", ".join(duplicates[:10]))
    return sorted(
        descriptors,
        key=lambda item: (
            item.canonical_identity is None,
            item.canonical_identity or "",
            item.exact_name,
        ),
    )


def qwen2_gguf_semantic_view(
    inventory: GGUFInventory,
) -> list[SemanticTensorDescriptor]:
    """Compatibility wrapper for the former Phase 4B public helper."""
    from omiv.model_packs.qwen2 import Qwen2ModelPack

    return gguf_semantic_view(inventory, Qwen2ModelPack())


Qwen2GGUFClassification = TensorClassification


def classify_qwen2_gguf_name(name: str) -> TensorClassification:
    """Compatibility wrapper for the former Phase 4B classifier."""
    from omiv.model_packs.qwen2.gguf_ontology import classify_gguf_tensor

    return classify_gguf_tensor(name)


def hf_semantic_view(inventory: HFInventory) -> list[SemanticTensorDescriptor]:
    """Return physical and logical HF semantic entities in stable identity order."""
    descriptors: list[SemanticTensorDescriptor] = []
    physical_by_identity: dict[str, SemanticTensorDescriptor] = {}
    for tensor in inventory.tensors:
        canonical = tensor.canonical
        descriptor = SemanticTensorDescriptor(
            exact_name=tensor.source_name,
            canonical_identity=None if canonical is None else canonical.identity,
            classification=tensor.classification,
            scope=None if canonical is None else canonical.scope,
            layer_id=None if canonical is None else canonical.layer_id,
            module=None if canonical is None else canonical.module,
            component=None if canonical is None else canonical.component,
            parameter=None if canonical is None else canonical.parameter,
            source_kind=SourceKind.PHYSICAL,
            materialized=True,
            shape=tensor.shape,
            shape_order="huggingface_safetensors",
            data_type=tensor.dtype,
        )
        descriptors.append(descriptor)
        if descriptor.canonical_identity is not None:
            if descriptor.canonical_identity in physical_by_identity:
                raise OmivInputError(
                    f"duplicate HF canonical identity: {descriptor.canonical_identity}"
                )
            physical_by_identity[descriptor.canonical_identity] = descriptor

    logical_seen: set[str] = set()
    for tie in inventory.logical_ties:
        if tie.logical_identity in logical_seen:
            raise OmivInputError(f"duplicate HF logical canonical identity: {tie.logical_identity}")
        logical_seen.add(tie.logical_identity)
        physical = physical_by_identity.get(tie.physical_source_identity)
        logical_canonical = next(
            (
                tensor.canonical
                for tensor in inventory.tensors
                if tensor.canonical is not None
                and tensor.canonical.identity == tie.logical_identity
            ),
            None,
        )
        descriptors.append(
            SemanticTensorDescriptor(
                exact_name=tie.logical_identity,
                canonical_identity=tie.logical_identity,
                classification="classified",
                scope=("model" if logical_canonical is None else logical_canonical.scope),
                layer_id=(None if logical_canonical is None else logical_canonical.layer_id),
                module=("output" if logical_canonical is None else logical_canonical.module),
                component=(
                    "output_projection"
                    if logical_canonical is None
                    else logical_canonical.component
                ),
                parameter=("weight" if logical_canonical is None else logical_canonical.parameter),
                source_kind=SourceKind.LOGICAL,
                materialized=tie.materialized,
                shape=[] if physical is None else physical.shape,
                shape_order="logical",
                data_type=None if physical is None else physical.data_type,
                physical_source_identity=tie.physical_source_identity,
            )
        )
    return sorted(
        descriptors,
        key=lambda item: (
            item.canonical_identity is None,
            item.canonical_identity or "",
            item.source_kind.value,
            item.exact_name,
        ),
    )
