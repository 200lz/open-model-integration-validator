"""Tiny test-only pack proving the core engine is not tied to production families."""

from __future__ import annotations

import re
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.models import (
    CanonicalTensorIdentity,
    HFConfigSummary,
    HFDiagnostic,
    HFTensorDescriptor,
    LogicalTensorTie,
)
from omiv.mapping.models import MappingManifest
from omiv.model_packs.base import (
    ModelPack,
    ModelPackCapability,
    TensorClassification,
)

_HF_RE = re.compile(r"^layers\.([01])\.linear\.weight$")
_GGUF_RE = re.compile(r"^blk\.([01])\.linear\.weight$")


def _classification(name: str, pattern: re.Pattern[str]) -> TensorClassification:
    match = pattern.fullmatch(name)
    if match is None:
        return TensorClassification(canonical=None)
    layer_id = int(match.group(1))
    return TensorClassification(
        canonical=CanonicalTensorIdentity(
            identity=f"synthetic-dense.layer.{layer_id}.ffn.linear.weight",
            scope="layer",
            layer_id=layer_id,
            module="ffn",
            component="linear",
            parameter="weight",
        ),
        layer_component="linear.weight",
    )


class SyntheticDenseModelPack(ModelPack):
    pack_id = "synthetic-dense"
    pack_version = 1
    model_family = "synthetic-dense"
    description = "Test-only two-layer dense mapping pack."
    capabilities = frozenset(
        {
            ModelPackCapability.HF_ONTOLOGY,
            ModelPackCapability.GGUF_ONTOLOGY,
            ModelPackCapability.SEMANTIC_MAPPING,
        }
    )
    supported_source_formats = frozenset({"huggingface-safetensors"})
    supported_target_formats = frozenset({"gguf"})
    production_supported = False
    test_only = True

    def classify_hf_tensor(self, name: str) -> TensorClassification:
        return _classification(name, _HF_RE)

    def classify_gguf_tensor(self, name: str) -> TensorClassification:
        return _classification(name, _GGUF_RE)

    def validate_hf_config(self, raw: dict[str, Any]) -> HFConfigSummary:
        if raw.get("model_type") != self.model_family:
            raise OmivInputError("selected model pack does not match config model_type")
        try:
            return HFConfigSummary(
                architectures=list(raw["architectures"]),
                model_type=str(raw["model_type"]),
                torch_dtype=str(raw["torch_dtype"]),
                tie_word_embeddings=bool(raw["tie_word_embeddings"]),
                hidden_size=int(raw["hidden_size"]),
                layer_count=int(raw["num_hidden_layers"]),
                attention_head_count=int(raw["num_attention_heads"]),
                key_value_head_count=int(raw["num_key_value_heads"]),
                intermediate_size=int(raw["intermediate_size"]),
                vocabulary_size=int(raw["vocab_size"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OmivInputError(f"invalid synthetic config: {exc}") from exc

    def validate_hf_structure(
        self,
        tensors: list[HFTensorDescriptor],
        config: HFConfigSummary,
    ) -> tuple[list[LogicalTensorTie], list[HFDiagnostic]]:
        expected = {"layers.0.linear.weight", "layers.1.linear.weight"}
        observed = {tensor.source_name for tensor in tensors}
        if config.layer_count != 2 or observed != expected:
            raise OmivInputError("synthetic dense pack requires exactly two linear layers")
        return [], []

    def load_default_mapping_manifest(self) -> MappingManifest:
        rules = []
        for layer_id in range(2):
            identity = f"synthetic-dense.layer.{layer_id}.ffn.linear.weight"
            rules.append(
                {
                    "rule_id": f"linear-{layer_id}",
                    "source": {"canonical_identity": identity},
                    "target": {
                        "canonical_identity": identity,
                        "tensor_name": f"blk.{layer_id}.linear.weight",
                    },
                    "source_kind": "physical",
                    "cardinality": "one_to_one",
                    "shape_relation": "reverse_dimensions",
                    "payload_transform": "identity",
                    "parameter": "weight",
                }
            )
        return MappingManifest.model_validate(
            {
                "mapping_schema": "omiv.semantic-mapping.v1",
                "mapping_id": "synthetic-dense-test",
                "model_family": self.model_family,
                "model_pack": {
                    "pack_id": self.pack_id,
                    "pack_schema_version": self.pack_schema_version,
                    "minimum_pack_version": self.pack_version,
                },
                "source_format": "huggingface-safetensors",
                "target_format": "gguf",
                "rules": rules,
            }
        )
